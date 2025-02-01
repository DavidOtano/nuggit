#ifndef NG_CONFIG_H
#define NG_CONFIG_H

#include <filesystem>
#include <cstdlib>
#include <string>

namespace ng {
namespace fs = std::filesystem;
static const fs::path& get_config_file_path(const std::string& filename) {
    static thread_local fs::path result;
    const auto config_path = std::getenv("NG_CONFIG_PATH");
    if (config_path) {
        result = fs::path(config_path) / fs::path(filename);
    } else {
        result = fs::path(filename);
    }
    return result;
}
}  // namespace ng

#endif
