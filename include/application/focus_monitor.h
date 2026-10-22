#pragma once

#include "engine/trust_scorer.h"
#include "enforcement/pidfd_manager.h"

#include <sys/types.h>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

struct FocusProcess {
    pid_t pid = -1;
    pid_t ppid = -1;
    std::string name;
    std::string exe;
    long pss_kb = 0;
    long baseline_pss_kb = 0;
    long previous_pss_kb = 0;
    long pss_delta_kb = 0;
    unsigned long cpu_ticks = 0;
    unsigned long previous_cpu_ticks = 0;
    unsigned long cpu_delta = 0;
    int score = 5000;
    int penalty_total = 0;
    AuthState state = AuthState::OBSERVED;
    bool active = false;
    bool suspended = false;
    std::unique_ptr<PidfdManager> pidfd;
};

class FocusMonitor {
public:
    explicit FocusMonitor(std::string application);
    int run();

private:
    std::string application_name;
    pid_t root_pid = -1;
    std::unordered_map<pid_t, std::shared_ptr<FocusProcess>> processes;
    int warmup_cycles = 6;
    unsigned long tick = 0;

    bool resolve_root();
    void refresh_tree();
    void profile_processes();
    void authorize_resources();
    void evaluate_behavior(std::shared_ptr<FocusProcess>& process);
    void enforce(std::shared_ptr<FocusProcess>& process, AuthState old_state);
    void render() const;

    static bool read_process_info(pid_t pid, pid_t& ppid, std::string& name, std::string& exe);
    static std::vector<pid_t> list_pids();
    bool is_descendant(pid_t pid, pid_t ancestor) const;
    std::string state_string(AuthState state) const;
    static std::string short_name(const std::string& name, size_t width);
};
