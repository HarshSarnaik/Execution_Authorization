#pragma once
#include <sys/types.h>

class ResourceMonitor {
public:
    // Returns the true memory cost (Proportional Set Size) in Kilobytes
    static long get_pss_kb(pid_t pid);
    
    // Returns the sum of user (utime) and kernel (stime) execution ticks
    static unsigned long get_cpu_ticks(pid_t pid);
};
