#pragma once
#include "concurrency/lockfree_queue.h"
#include <vector>
#include <thread>
#include <functional>

class ThreadPool {
private:
    std::vector<std::thread> workers;
    ThreadSafeQueue<std::function<void()>> tasks;

public:
    explicit ThreadPool(size_t num_threads);
    ~ThreadPool();
    void enqueue(std::function<void()> task);
    void shutdown();
};
