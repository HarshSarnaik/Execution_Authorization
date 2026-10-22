#include "profiler/resource_monitor.h"
#include <fstream>
#include <string>
#include <sstream>
#include <vector>

long ResourceMonitor::get_pss_kb(pid_t pid) {
    // smaps_rollup is a modern kernel feature that computes PSS without needing 
    // to walk the entire page table manually in userspace.
    std::ifstream file("/proc/" + std::to_string(pid) + "/smaps_rollup");
    std::string line;
    while (std::getline(file, line)) {
        if (line.compare(0, 4, "Pss:") == 0) {
            long pss = 0;
            std::string label, unit;
            std::istringstream iss(line);
            iss >> label >> pss >> unit;
            return pss;
        }
    }
    return 0; // Returns 0 if process terminated during the read race
}

unsigned long ResourceMonitor::get_cpu_ticks(pid_t pid) {
    std::ifstream file("/proc/" + std::to_string(pid) + "/stat");
    std::string line;
    if (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string token;
        std::vector<std::string> tokens;
        while (iss >> token) {
            tokens.push_back(token);
        }
        if (tokens.size() > 14) {
            // Column 14 (idx 13) is utime, Column 15 (idx 14) is stime
            return std::stoul(tokens[13]) + std::stoul(tokens[14]);
        }
    }
    return 0;
}
