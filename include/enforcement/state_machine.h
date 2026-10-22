#pragma once
class StateMachine;
extern StateMachine eal_state_machine;

#include "engine/trust_scorer.h"
#include "enforcement/pidfd_manager.h"
#include <unordered_map>
#include <memory>
#include <string>

struct ProcessRecord {
    pid_t pid;
    std::string hash;
    int score;
    long baseline_pss = 0;
    unsigned long baseline_cpu = 0;
    bool is_whitelisted = false; // The missing immunity flag
    AuthState state;
    std::unique_ptr<PidfdManager> pidfd;
};

class StateMachine {
private:
    std::unordered_map<pid_t, std::shared_ptr<ProcessRecord>> process_registry;
    void enforce_state(std::shared_ptr<ProcessRecord> record);
    std::string state_to_string(AuthState state);

public:
    void register_process(pid_t pid, const std::string& hash);
    void penalize_process(pid_t pid, int penalty);
    void remove_process(pid_t pid);
    void profile_and_evaluate();
};
