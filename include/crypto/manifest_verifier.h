#pragma once
#include <string>
#include <unordered_set>

class ManifestVerifier {
private:
    static std::unordered_set<std::string> whitelisted_hashes;

public:
    static void load_manifest(const std::string& config_path);
    static void add_hash(const std::string& hash);
    static bool is_whitelisted(const std::string& hash);
};
