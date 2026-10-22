#include "crypto/evp_verifier.h"
#include <openssl/evp.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <iomanip>
#include <sstream>
#include <iostream>

std::string CryptoVerifier::calculate_sha256(pid_t pid) {
    // Resolve the binary directly from kernel memory mappings to avoid TOCTOU races
    std::string proc_path = "/proc/" + std::to_string(pid) + "/exe";
    
    // O_CLOEXEC prevents file descriptor leaks if we happen to fork
    int fd = open(proc_path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        // Kernel threads and heavily sandboxed processes might deny read access
        return "UNREADABLE_OR_KERNEL_THREAD";
    }

    // RAII wrapper for the OpenSSL EVP_MD_CTX to ensure absolute memory safety
    using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    EVP_MD_CTX_ptr mdctx(EVP_MD_CTX_new(), ::EVP_MD_CTX_free);

    if (!mdctx || EVP_DigestInit_ex(mdctx.get(), EVP_sha256(), nullptr) != 1) {
        close(fd);
        return "EVP_INIT_FAILED";
    }

    char buffer[16384]; // 16KB chunks to prevent memory spikes on large binaries
    ssize_t bytes_read;
    
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        if (EVP_DigestUpdate(mdctx.get(), buffer, bytes_read) != 1) {
            close(fd);
            return "EVP_UPDATE_FAILED";
        }
    }

    close(fd);

    if (bytes_read < 0) {
        return "FILE_READ_ERROR";
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int lengthOfHash = 0;

    if (EVP_DigestFinal_ex(mdctx.get(), hash, &lengthOfHash) != 1) {
        return "EVP_FINAL_FAILED";
    }

    // Convert raw bytes to hex string
    std::stringstream ss;
    for (unsigned int i = 0; i < lengthOfHash; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}
