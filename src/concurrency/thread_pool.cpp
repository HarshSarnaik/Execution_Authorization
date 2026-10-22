#include "concurrency/thread_pool.h"
#include <iostream>

ThreadPool::ThreadPool(size_t num_threads) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([this, i]() {
            while (true) {
                auto task = tasks.pop();
                if (!task.has_value()) {
                    break; // Queue shutdown signaled
                }
                // Execute the dispatched task (e.g., Cryptographic Hashing)
                (*task)(); 
            }
        });
    }
    std::cout << "[*] Thread pool initialized with " << num_threads << " workers.\n";
}

ThreadPool::~ThreadPool() {
    shutdown();
}

void ThreadPool::enqueue(std::function<void()> task) {
    tasks.push(std::move(task));
}

void ThreadPool::shutdown() {
    tasks.shutdown();
    for (std::thread &worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}
