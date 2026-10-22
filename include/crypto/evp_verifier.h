#pragma once

#include <string>
#include <sys/types.h>

class CryptoVerifier {
public:
    // Computes the SHA-256 hash of the binary executed by the given PID
    static std::string calculate_sha256(pid_t pid);
};
