#include "enforcement/state_machine.h"
#include "crypto/manifest_verifier.h"
#include "profiler/resource_monitor.h"
#include <iostream>

std::string StateMachine::state_to_string(AuthState state) {
    switch(state) {
        case AuthState::TRUSTED: return "\033[1;32mTRUSTED\033[0m";
        case AuthState::OBSERVED: return "\033[1;33mOBSERVED\033[0m";
        case AuthState::RESTRICTED: return "\033[1;31mRESTRICTED\033[0m";
        case AuthState::QUARANTINED: return "\033[1;35mQUARANTINED\033[0m";
    }
    return "UNKNOWN";
}

void StateMachine::register_process(pid_t pid, const std::string& hash) {
    auto record = std::make_shared<ProcessRecord>();
    record->pid = pid;
    record->hash = hash;
    record->pidfd = std::make_unique<PidfdManager>(pid);

    // Check Whitelist Manifest & Kernel Thread Exemption
    if (ManifestVerifier::is_whitelisted(hash) || 
        hash == "UNREADABLE_OR_KERNEL_THREAD" || 
        hash == "FILE_READ_ERROR") {
        
        record->score = TrustScorer::MAX_SCORE;
        record->state = AuthState::TRUSTED;
        record->is_whitelisted = true; // IMMUNITY GRANTED
        
        std::cout << "[STATE] Registered PID " << pid << " | Hash: " << hash.substr(0, 12) 
                  << "... | Score: 10000 | State: " << state_to_string(record->state) 
                  << " \033[1;36m[WHITELIST IMMUNE]\033[0m\n";
    } else {
        record->score = 5000;
        record->state = AuthState::OBSERVED;
        record->is_whitelisted = false;
        
        std::cout << "[STATE] Registered PID " << pid << " | Hash: " << hash.substr(0, 12) 
                  << "... | Score: 5000 | State: " << state_to_string(record->state) << "\n";
    }

    process_registry[pid] = record;
    enforce_state(record);
}

void StateMachine::penalize_process(pid_t pid, int penalty) {
    auto it = process_registry.find(pid);
    if (it == process_registry.end()) return;

    auto record = it->second;

    // HARD GUARD: Whitelisted binaries are strictly immune to penalties
    if (record->is_whitelisted) {
        return; 
    }

    int old_score = record->score;
    record->score = TrustScorer::apply_penalty(record->score, penalty);
    AuthState new_state = TrustScorer::evaluate_transition(record->state, record->score);
    
    std::cout << "[SCORE] PID " << pid << " penalized by " << penalty 
              << ". Score dropped from " << old_score << " to " << record->score << ".\n";
              
    if (new_state != record->state) {
        std::cout << "[STATE] PID " << pid << " transitioned: " << state_to_string(record->state) 
                  << " -> " << state_to_string(new_state) << "\n";
        record->state = new_state;
        enforce_state(record);
    }
}

void StateMachine::enforce_state(std::shared_ptr<ProcessRecord> record) {
    if (!record->pidfd->is_valid() || record->is_whitelisted) return;

    switch (record->state) {
        case AuthState::RESTRICTED:
            std::cout << "[ENFORCE] Freezing PID " << record->pid << " (SIGSTOP via PIDFD)\n";
            record->pidfd->suspend();
            break;
        case AuthState::QUARANTINED:
            std::cout << "[ENFORCE] Eradicating PID " << record->pid << " (SIGKILL via PIDFD)\n";
            record->pidfd->kill();
            break;
        default:
            break;
    }
}

void StateMachine::remove_process(pid_t pid) {
    process_registry.erase(pid);
}

void StateMachine::profile_and_evaluate() {
    for (auto it = process_registry.begin(); it != process_registry.end(); ++it) {
        auto record = it->second;
        if (record->state == AuthState::OBSERVED && !record->is_whitelisted) {
            long current_pss = ResourceMonitor::get_pss_kb(record->pid);
            if (current_pss > 0) {
                if (record->baseline_pss == 0) {
                    record->baseline_pss = current_pss;
                } else {
                    long diff = current_pss - record->baseline_pss;
                    if (diff > 50000) { // 50MB spike
                        std::cout << "\n[ANOMALY] PID " << record->pid << " rapidly allocated " 
                                  << (diff / 1024) << " MB of memory.\n";
                        penalize_process(record->pid, 2000);
                        record->baseline_pss = current_pss;
                    }
                }
            }
        }
    }
}
