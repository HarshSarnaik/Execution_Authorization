#include "application/focus_monitor.h"

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Usage: eal_focus <application_name>\n";
        return 64;
    }

    FocusMonitor monitor(argv[1]);
    return monitor.run();
}
