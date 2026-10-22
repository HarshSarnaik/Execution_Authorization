#include "crypto/manifest_verifier.h"
#include <iostream>
#include <csignal>
#include <thread>
#include <sys/timerfd.h>
#include <unistd.h>
#include "telemetry/netlink_conn.h"
#include "concurrency/thread_pool.h"
#include "concurrency/epoll_loop.h"
#include "enforcement/state_machine.h"

EpollLoop* global_epoll_ptr = nullptr;

void signal_handler(int signum) {
    std::cout << "\n[!] Caught signal " << signum << " (SIGINT/SIGTERM).\n";
    std::cout << "[!] Initiating graceful EAL shutdown...\n";
    if (global_epoll_ptr) {
        global_epoll_ptr->stop();
    }
}

int main() {
    std::setvbuf(stdout, NULL, _IONBF, 0);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "[*] Execution Authorization Layer (EAL) Starting...\n";

    unsigned int hardware_threads = std::thread::hardware_concurrency();
    ThreadPool thread_pool(hardware_threads > 0 ? hardware_threads : 4);

    EpollLoop epoll_loop(thread_pool);
    if (!epoll_loop.init()) return 1;
    global_epoll_ptr = &epoll_loop;

    ManifestVerifier::load_manifest("/etc/eal/default_manifest.json");
    NetlinkTelemetry telemetry;
    if (!telemetry.init() || !telemetry.subscribe()) {
        std::cerr << "[-] Telemetry failure. Are you running as root?\n";
        return 1;
    }

    epoll_loop.register_fd(telemetry.get_fd(), EPOLLIN, [&telemetry](uint32_t events) {
        if (events & EPOLLIN) telemetry.process_events();
    });

    // --- NEW: Asynchronous Profiling Timer ---
    // Create a timer file descriptor that fires every 2 seconds
    int timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    struct itimerspec ts = {};
    ts.it_interval.tv_sec = 2; // Tick every 2 seconds
    ts.it_value.tv_sec = 2;
    timerfd_settime(timer_fd, 0, &ts, NULL);

    // Register the timer with the epoll fast-path
    epoll_loop.register_fd(timer_fd, EPOLLIN, [timer_fd](uint32_t events) {
        if (events & EPOLLIN) {
            uint64_t expirations;
            // Acknowledge the timer tick to reset the FD
            if (read(timer_fd, &expirations, sizeof(expirations)) > 0) {
                eal_state_machine.profile_and_evaluate();
            }
        }
    });

    std::cout << "[+] EAL Daemon is active and enforcing policies. (Press Ctrl+C to stop)\n";

    epoll_loop.run();
    close(timer_fd);
    
    std::cout << "[+] EAL Daemon shut down cleanly.\n";
    return 0;
}
