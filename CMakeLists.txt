cmake_minimum_required(VERSION 3.15)
project(ExecutionAuthorizationLayer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enforce strict compilation warnings for a security daemon
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O3")

# Find system libraries
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Include header directories
include_directories(include)

# Glob all source files
file(GLOB_RECURSE SOURCES "src/*.cpp")
# Focus Mode is a separate executable; keep its implementation out of the daemon.
list(FILTER SOURCES EXCLUDE REGEX ".*/src/application/focus_monitor(_main)?\.cpp$")

# Define the daemon executable
add_executable(eal_daemon ${SOURCES})

# Link OpenSSL and Pthreads
target_link_libraries(eal_daemon PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
