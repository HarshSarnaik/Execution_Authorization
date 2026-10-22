#include "concurrency/epoll_loop.h"
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <iostream>

EpollLoop::EpollLoop(ThreadPool& pool) : thread_pool(pool) {}

EpollLoop::~EpollLoop() {
    if (epoll_fd >= 0) close(epoll_fd);
}

bool EpollLoop::init() {
    // epoll_create1 with EPOLL_CLOEXEC for security against FD leaks across forks
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) {
        std::cerr << "[-] epoll_create1 failed: " << strerror(errno) << "\n";
        return false;
    }
    return true;
}

bool EpollLoop::register_fd(int fd, uint32_t events, std::function<void(uint32_t)> handler) {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        std::cerr << "[-] epoll_ctl ADD failed for FD " << fd << ": " << strerror(errno) << "\n";
        return false;
    }
    
    fd_handlers[fd] = std::move(handler);
    return true;
}

bool EpollLoop::unregister_fd(int fd) {
    fd_handlers.erase(fd);
    return epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr) != -1;
}

void EpollLoop::run() {
    const int MAX_EVENTS = 64;
    struct epoll_event events[MAX_EVENTS];

    std::cout << "[*] Epoll I/O multiplexer armed. Entering fast-path event loop...\n";

    while (running) {
        // Block until an FD is ready, or timeout after 500ms to allow clean shutdown checks
        int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, 500);

        if (num_events == -1) {
            if (errno == EINTR) continue; // Interrupted by a signal (e.g., SIGTERM), loop will catch 'running == false'
            std::cerr << "[-] epoll_wait error: " << strerror(errno) << "\n";
            break;
        }

        for (int i = 0; i < num_events; ++i) {
            int ready_fd = events[i].data.fd;
            uint32_t ready_events = events[i].events;

            auto it = fd_handlers.find(ready_fd);
            if (it != fd_handlers.end()) {
                // Instantly offload the I/O parsing to the Thread Pool
                // The fast-path thread immediately goes back to epoll_wait
                auto handler = it->second;
                thread_pool.enqueue([handler, ready_events]() {
                    handler(ready_events);
                });
            }
        }
    }
}

void EpollLoop::stop() {
    running = false;
}
