#pragma once
#include "concurrency/thread_pool.h"
#include <sys/epoll.h>
#include <unordered_map>
#include <functional>
#include <atomic>

class EpollLoop {
private:
    int epoll_fd = -1;
    ThreadPool& thread_pool;
    std::unordered_map<int, std::function<void(uint32_t)>> fd_handlers;
    std::atomic<bool> running{true};

public:
    explicit EpollLoop(ThreadPool& pool);
    ~EpollLoop();

    bool init();
    bool register_fd(int fd, uint32_t events, std::function<void(uint32_t)> handler);
    bool unregister_fd(int fd);
    
    // The main fast-path blocking loop
    void run();
    void stop();
};
