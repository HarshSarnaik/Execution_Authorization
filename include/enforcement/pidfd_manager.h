#pragma once
#include <sys/types.h>

class PidfdManager {
private:
    int pidfd = -1;
    pid_t target_pid = -1;

public:
    // Attempts to acquire a stable file descriptor for the given PID
    explicit PidfdManager(pid_t pid);
    ~PidfdManager();

    // Delete copy constructors to prevent double-closing the same file descriptor
    PidfdManager(const PidfdManager&) = delete;
    PidfdManager& operator=(const PidfdManager&) = delete;

    // Allow move semantics
    PidfdManager(PidfdManager&& other) noexcept;
    PidfdManager& operator=(PidfdManager&& other) noexcept;

    bool is_valid() const { return pidfd >= 0; }
    int get_fd() const { return pidfd; }
    pid_t get_pid() const { return target_pid; }

    // Race-free enforcement actions
    bool send_signal(int sig);
    bool suspend(); // Sends SIGSTOP
    bool resume();  // Sends SIGCONT
    bool kill();    // Sends SIGKILL
};
