#include "crypto/manifest_verifier.h"
#include <fstream>
#include <iostream>
#include <algorithm>

std::unordered_set<std::string> ManifestVerifier::whitelisted_hashes;

void ManifestVerifier::load_manifest(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        std::cout << "[*] No pre-existing whitelist manifest found at " << config_path << "\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Strip whitespace and quotes
        line.erase(std::remove_if(line.begin(), line.end(), [](char c) {
            return c == ' ' || c == '"' || c == ',' || c == '\r' || c == '\n';
        }), line.end());

        if (!line.empty() && line.length() == 64) { // Valid SHA-256 hash length
            whitelisted_hashes.insert(line);
        }
    }
    std::cout << "[+] Loaded " << whitelisted_hashes.size() << " whitelisted SHA-256 hashes into memory.\n";
}

void ManifestVerifier::add_hash(const std::string& hash) {
    if (hash.length() == 64) {
        whitelisted_hashes.insert(hash);
    }
}

bool ManifestVerifier::is_whitelisted(const std::string& hash) {
    return whitelisted_hashes.find(hash) != whitelisted_hashes.end();
}
