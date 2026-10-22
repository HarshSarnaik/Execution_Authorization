#include "enforcement/pidfd_manager.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <csignal>
#include <iostream>
#include <cerrno>
#include <cstring>

// Define raw syscall numbers if older kernel headers are present
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

PidfdManager::PidfdManager(pid_t pid) : target_pid(pid) {
    // Acquire the file descriptor directly from the kernel task structure
    pidfd = syscall(SYS_pidfd_open, pid, 0);
}

PidfdManager::~PidfdManager() {
    if (pidfd >= 0) {
        close(pidfd); // Securely release the file descriptor
    }
}

PidfdManager::PidfdManager(PidfdManager&& other) noexcept : pidfd(other.pidfd), target_pid(other.target_pid) {
    other.pidfd = -1;
    other.target_pid = -1;
}

PidfdManager& PidfdManager::operator=(PidfdManager&& other) noexcept {
    if (this != &other) {
        if (pidfd >= 0) close(pidfd);
        pidfd = other.pidfd;
        target_pid = other.target_pid;
        other.pidfd = -1;
        other.target_pid = -1;
    }
    return *this;
}

bool PidfdManager::send_signal(int sig) {
    if (pidfd < 0) return false;
    
    // Route the signal directly to the task via the file descriptor
    int ret = syscall(SYS_pidfd_send_signal, pidfd, sig, NULL, 0);
    if (ret == -1) {
        // ESRCH indicates the process exited naturally before we signaled it.
        // This is the EXACT scenario that causes accidental collateral damage with legacy kill().
        if (errno != ESRCH) {
            std::cerr << "[-] Failed to signal PID " << target_pid << ": " << strerror(errno) << "\n";
        }
        return false;
    }
    return true;
}

bool PidfdManager::suspend() { return send_signal(SIGSTOP); }
bool PidfdManager::resume() { return send_signal(SIGCONT); }
bool PidfdManager::kill() { return send_signal(SIGKILL); }
