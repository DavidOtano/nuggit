#ifndef NG_COLOR_FORMATTER_H
#define NG_COLOR_FORMATTER_H

#include <charconv>
#include <format>
#include <sstream>
#include <string>
#include <cstdint>
#include "random.h"

#define AVAILABLE_COLOR_COLUMNS 10

namespace ng::wpn::chat {

using namespace ng::utils;

[[nodiscard]] constexpr std::string COL(const char code) {
    std::string result = "";
    result += "\x3";
    result += code;
    return result;
}

[[nodiscard]] static bool parse_color(std::string_view str, size_t& idx,
                                      uint8_t& curr_color) noexcept {
    const uint8_t available_colors[] = {
#include "available_colors.inc"
    };

    if (idx + 3 > str.length()) {
        return false;
    }

    if (str[idx] == '#' && str[idx + 1] == 'c') {
        if (str[idx + 2] == '0') {
            return false;
        }

        if (auto pos = str.find('#', idx + 2); pos != std::string::npos &&
                                               pos - (idx + 2) <= 3 &&
                                               pos - (idx + 2) > 0) {
            if (str[idx + 2] == '?' && str[idx + 3] == '#') {
                curr_color = available_colors[random::next(
                    0, static_cast<int>(sizeof available_colors) - 1)];
            } else {
                for (auto i = idx + 2; i < pos; ++i) {
                    if (!std::isdigit(str[i])) {
                        return false;
                    }
                }

                uint32_t col = 0;
                std::from_chars(str.data() + idx + 2, str.data() + pos, col);
                if (col > 255) {
                    return false;
                }
                curr_color = (uint8_t)col;
            }

            idx = pos;
            return true;
        }
    }

    return false;
}

[[nodiscard]] static std::string format_colorful_string(
    std::string_view str, bool strip_colors = false) noexcept {
    std::ostringstream stream;

    uint8_t curr_color = 0;
    for (size_t i = 0; i < str.length(); ++i) {
        if (parse_color(str, i, curr_color)) {
            continue;
        }

        if (curr_color && !strip_colors) {
            char code[3] = {0x3, (char)curr_color, 0};
            stream << code;
            curr_color = 0;
        }

        stream << str[i];
    }

    return stream.str();
}

[[nodiscard]] constexpr const std::string list_available_colors() {
    std::string result;

    const uint8_t available_colors[] = {
#include "available_colors.inc"
    };

    for (size_t i = 0; i < sizeof available_colors; ++i) {
        result += COL(available_colors[i]);
        result += std::format("#c{}#  ", (int)available_colors[i]);
        if (i % AVAILABLE_COLOR_COLUMNS == AVAILABLE_COLOR_COLUMNS - 1) {
            result += '\n';
        }
    }

    return result;
}

}  // namespace ng::wpn::chat

#endif
