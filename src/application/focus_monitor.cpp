#include "application/focus_monitor.h"
#include "profiler/resource_monitor.h"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <csignal>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits.h>
#include <sstream>
#include <thread>
#include <unistd.h>

namespace {
constexpr long MEMORY_SPIKE_KB = 50 * 1024;
constexpr int RESOURCE_PENALTY = 2500;
volatile sig_atomic_t g_stop = 0;
void stop_handler(int) { g_stop = 1; }
}

FocusMonitor::FocusMonitor(std::string application)
    : application_name(std::move(application)) {}

std::vector<pid_t> FocusMonitor::list_pids() {
    std::vector<pid_t> result;
    DIR* dir = opendir("/proc");
    if (!dir) return result;

    while (auto* entry = readdir(dir)) {
        if (entry->d_type != DT_DIR) continue;
        char* end = nullptr;
        long value = std::strtol(entry->d_name, &end, 10);
        if (end && *end == '\0' && value > 0 && value <= std::numeric_limits<pid_t>::max()) {
            result.push_back(static_cast<pid_t>(value));
        }
    }
    closedir(dir);
    return result;
}

bool FocusMonitor::read_process_info(pid_t pid, pid_t& ppid, std::string& name, std::string& exe) {
    std::ifstream stat("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (!std::getline(stat, line)) return false;

    const auto left = line.find('(');
    const auto right = line.rfind(')');
    if (left == std::string::npos || right == std::string::npos || right <= left) return false;

    name = line.substr(left + 1, right - left - 1);
    std::istringstream rest(line.substr(right + 2)); // state is token 1 after ')'
    char state = 0;
    if (!(rest >> state >> ppid)) return false;

    char path[PATH_MAX];
    const std::string link = "/proc/" + std::to_string(pid) + "/exe";
    const ssize_t n = readlink(link.c_str(), path, sizeof(path) - 1);
    if (n > 0) {
        path[n] = '\0';
        exe = path;
    } else {
        exe.clear();
    }
    return true;
}

bool FocusMonitor::resolve_root() {
    std::vector<pid_t> candidates;
    for (pid_t pid : list_pids()) {
        if (pid == getpid()) continue;
        pid_t ppid;
        std::string name, exe;
        if (!read_process_info(pid, ppid, name, exe)) continue;

        std::string basename = exe;
        const auto slash = basename.rfind('/');
        if (slash != std::string::npos) basename.erase(0, slash + 1);

        if (name == application_name || basename == application_name || exe == application_name) {
            candidates.push_back(pid);
        }
    }

    if (candidates.empty()) return false;
    root_pid = *std::min_element(candidates.begin(), candidates.end());
    return true;
}

bool FocusMonitor::is_descendant(pid_t pid, pid_t ancestor) const {
    if (pid == ancestor) return true;

    pid_t current = pid;
    for (int depth = 0; depth < 64 && current > 1; ++depth) {
        pid_t ppid;
        std::string name, exe;
        if (!read_process_info(current, ppid, name, exe)) return false;
        if (ppid == ancestor) return true;
        if (ppid == current) return false;
        current = ppid;
    }
    return false;
}

void FocusMonitor::refresh_tree() {
    std::unordered_map<pid_t, std::shared_ptr<FocusProcess>> next;

    if (root_pid <= 0) return;

    for (pid_t pid : list_pids()) {
        if (!is_descendant(pid, root_pid)) continue;

        pid_t ppid;
        std::string name, exe;
        if (!read_process_info(pid, ppid, name, exe)) continue;

        auto it = processes.find(pid);
        if (it == processes.end()) {
            auto p = std::make_shared<FocusProcess>();
            p->pid = pid;
            p->ppid = ppid;
            p->name = name;
            p->exe = exe;
            p->pss_kb = ResourceMonitor::get_pss_kb(pid);
            p->baseline_pss_kb = p->pss_kb;
            p->previous_pss_kb = p->pss_kb;
            p->cpu_ticks = ResourceMonitor::get_cpu_ticks(pid);
            p->previous_cpu_ticks = p->cpu_ticks;
            p->pidfd = std::make_unique<PidfdManager>(pid);
            next[pid] = p;
            std::cout << "[FOCUS] PROCESS ADDED  PID=" << pid << " PPID=" << ppid
                      << " NAME=" << name << "\n";
        } else {
            auto p = it->second;
            p->ppid = ppid;
            p->name = name;
            p->exe = exe;
            next[pid] = p;
        }
    }

    for (const auto& [pid, process] : processes) {
        if (!next.count(pid)) {
            if (process->suspended && process->pidfd && process->pidfd->is_valid()) {
                process->pidfd->resume();
            }
            std::cout << "[FOCUS] PROCESS EXITED  PID=" << pid << "\n";
        }
    }

    processes.swap(next);
}

void FocusMonitor::profile_processes() {
    for (auto& [pid, process] : processes) {
        const unsigned long now_cpu = ResourceMonitor::get_cpu_ticks(pid);
        process->cpu_delta = now_cpu >= process->previous_cpu_ticks
                                 ? now_cpu - process->previous_cpu_ticks
                                 : 0;
        process->previous_cpu_ticks = now_cpu;
        process->cpu_ticks = now_cpu;
        const long now_pss = ResourceMonitor::get_pss_kb(pid);
        process->pss_delta_kb = now_pss - process->previous_pss_kb;
        process->previous_pss_kb = now_pss;
        process->pss_kb = now_pss;
    }
}

void FocusMonitor::evaluate_behavior(std::shared_ptr<FocusProcess>& process) {
    if (process->pid == root_pid) return;
    if (process->state == AuthState::QUARANTINED) return;

    const long growth = process->pss_kb - process->baseline_pss_kb;
    if (growth > MEMORY_SPIKE_KB) {
        const int old_score = process->score;
        const AuthState old_state = process->state;
        process->score = TrustScorer::apply_penalty(process->score, RESOURCE_PENALTY);
        process->penalty_total += RESOURCE_PENALTY;
        process->state = TrustScorer::evaluate_transition(process->state, process->score);
        process->baseline_pss_kb = process->pss_kb;

        std::cout << "[FOCUS] RESOURCE ANOMALY PID=" << process->pid
                  << " PSS_GROWTH=" << growth / 1024 << "MB"
                  << " PENALTY=-" << RESOURCE_PENALTY
                  << " SCORE=" << old_score << "->" << process->score << "\n";

        if (process->state != old_state) {
            std::cout << "[FOCUS] AUTHORIZATION " << state_string(old_state)
                      << " -> " << state_string(process->state)
                      << " PID=" << process->pid << "\n";
            enforce(process, old_state);
        }
    }
}

void FocusMonitor::authorize_resources() {
    if (processes.size() <= 1) return;

    // During startup allow the process tree to establish a meaningful CPU profile.
    if (tick <= static_cast<unsigned long>(warmup_cycles)) {
        for (auto& [pid, p] : processes) {
            p->active = (pid == root_pid);
        }
        return;
    }

    pid_t active_pid = -1;
    unsigned long best_cpu = 0;
    for (auto& [pid, p] : processes) {
        if (pid == root_pid || p->state == AuthState::RESTRICTED || p->state == AuthState::QUARANTINED)
            continue;
        const bool active_signal = p->cpu_delta > 0 || p->pss_delta_kb > 4096;
        if (active_signal && p->cpu_delta >= best_cpu) {
            best_cpu = p->cpu_delta;
            active_pid = pid;
        }
    }

    for (auto& [pid, p] : processes) {
        if (pid == root_pid) {
            p->active = true;
            continue;
        }

        if (p->state == AuthState::QUARANTINED) {
            p->active = false;
            continue;
        }

        const bool should_run = (pid == active_pid);
        p->active = should_run;

        if (should_run) {
            if (p->suspended && p->pidfd && p->pidfd->is_valid()) {
                if (p->pidfd->resume()) {
                    p->suspended = false;
                    std::cout << "[FOCUS] RESOURCE GRANTED  PID=" << pid << " (SIGCONT)\n";
                }
            }
        } else {
            if (!p->suspended && p->pidfd && p->pidfd->is_valid()) {
                if (p->pidfd->suspend()) {
                    p->suspended = true;
                    std::cout << "[FOCUS] RESOURCE RECLAIMED PID=" << pid << " (IDLE -> SIGSTOP)\n";
                }
            }
        }
    }
}

void FocusMonitor::enforce(std::shared_ptr<FocusProcess>& process, AuthState old_state) {
    (void)old_state;
    if (!process->pidfd || !process->pidfd->is_valid()) return;

    if (process->state == AuthState::RESTRICTED) {
        if (process->pidfd->suspend()) {
            process->suspended = true;
            process->active = false;
            std::cout << "[FOCUS] ENFORCE RESTRICTED PID=" << process->pid << " -> SIGSTOP\n";
        }
    } else if (process->state == AuthState::QUARANTINED) {
        std::cout << "[FOCUS] ENFORCE QUARANTINED PID=" << process->pid << " -> SIGKILL\n";
        process->pidfd->kill();
    }
}

std::string FocusMonitor::state_string(AuthState state) const {
    switch (state) {
        case AuthState::TRUSTED: return "TRUSTED";
        case AuthState::OBSERVED: return "OBSERVED";
        case AuthState::RESTRICTED: return "RESTRICTED";
        case AuthState::QUARANTINED: return "QUARANTINED";
    }
    return "UNKNOWN";
}

std::string FocusMonitor::short_name(const std::string& name, size_t width) {
    if (name.size() <= width) return name;
    if (width <= 3) return name.substr(0, width);
    return name.substr(0, width - 3) + "...";
}

void FocusMonitor::render() const {
    std::cout << "\033[2J\033[H";
    std::cout << "==========================================================================\n";
    std::cout << " EAL — APPLICATION-SCOPED RUNTIME AUTHORIZATION\n";
    std::cout << " Focus: " << application_name << "  Root PID: " << root_pid
              << "  Cycle: " << tick << "\n";
    std::cout << " Policy: ACTIVE CHILD GETS RUNTIME | IDLE CHILDREN SUSPENDED\n";
    std::cout << "--------------------------------------------------------------------------\n";
    std::cout << std::left << std::setw(7) << "PID"
              << std::setw(7) << "PPID"
              << std::setw(18) << "PROCESS"
              << std::setw(10) << "PSS"
              << std::setw(10) << "CPU Δ"
              << std::setw(9) << "SCORE"
              << std::setw(14) << "STATE"
              << "ACTION\n";
    std::cout << "--------------------------------------------------------------------------\n";

    std::vector<std::shared_ptr<FocusProcess>> ordered;
    for (const auto& [pid, p] : processes) ordered.push_back(p);
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) { return a->pid < b->pid; });

    for (const auto& p : ordered) {
        std::string action;
        if (p->pid == root_pid) action = "ROOT / MONITOR";
        else if (p->state == AuthState::QUARANTINED) action = "SIGKILL";
        else if (p->state == AuthState::RESTRICTED) action = "SIGSTOP (ABNORMAL)";
        else if (p->active) action = "RUN / PRIORITY";
        else if (p->suspended) action = "SIGSTOP (IDLE)";
        else action = "WARMUP";

        std::ostringstream pss;
        pss << p->pss_kb / 1024 << "MB";
        std::cout << std::left << std::setw(7) << p->pid
                  << std::setw(7) << p->ppid
                  << std::setw(18) << short_name(p->name, 17)
                  << std::setw(10) << pss.str()
                  << std::setw(10) << p->cpu_delta
                  << std::setw(9) << p->score
                  << std::setw(14) << state_string(p->state)
                  << action << "\n";
    }
    std::cout << "--------------------------------------------------------------------------\n";
    std::cout << "Ctrl+C exits Focus Mode and resumes suspended children.\n";
    std::cout.flush();
}

int FocusMonitor::run() {
    if (geteuid() != 0) {
        std::cerr << "[-] Focus Mode requires root privileges for PIDFD enforcement.\n";
        return 1;
    }

    if (!resolve_root()) {
        std::cerr << "[-] Application not found: " << application_name << "\n";
        return 2;
    }

    std::cout << "[+] Focus root resolved: " << application_name << " PID=" << root_pid << "\n";

    std::signal(SIGINT, stop_handler);
    std::signal(SIGTERM, stop_handler);

    // Keep the loop simple and deterministic for the demonstration.
    while (!g_stop) {
        ++tick;
        refresh_tree();
        if (processes.find(root_pid) == processes.end()) {
            std::cout << "[FOCUS] Root application exited.\n";
            break;
        }

        profile_processes();
        for (auto& [pid, process] : processes) evaluate_behavior(process);
        authorize_resources();
        render();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    for (auto& [pid, process] : processes) {
        if (process->suspended && process->pidfd && process->pidfd->is_valid()) {
            process->pidfd->resume();
        }
    }
    return 0;
}
