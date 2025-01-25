#ifndef NG_STRING_UTILS_H
#define NG_STRING_UTILS_H

#include <algorithm>
#include <cctype>
#include <string>

namespace ng::string::utils {
[[maybe_unused]] static std::string trim(const std::string& str) noexcept {
    auto start = str.find_first_not_of(" \t");
    auto end = str.find_last_not_of(" \t");

    if (start == std::string::npos) {
        return str;
    }

    std::string ret = str.substr(start, end - start + 1);

    return ret;
}

[[maybe_unused]] static std::string& trim(std::string& str) noexcept {
    auto start = str.find_first_not_of(" \t");
    auto end = str.find_last_not_of(" \t");

    if (start == std::string::npos) {
        return str;
    }

    str = str.substr(start, end - start + 1);

    return str;
}

[[maybe_unused]] static std::string& to_lower(std::string& str) noexcept {
    std::transform(str.begin(), str.end(), str.begin(), tolower);
    return str;
}

[[maybe_unused]] static bool replace(std::string& str, const std::string& from,
                                     const std::string& to) {
    size_t start_pos = str.find(from);
    if (start_pos == std::string::npos) {
        return false;
    }
    str.replace(start_pos, from.length(), to);
    return true;
}
}  // namespace ng::string::utils

#endif
