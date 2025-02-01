#include <string-utils.h>
#include <fstream>
#include <sstream>
#include "logging.h"
#include "ini-parser.h"

namespace ng::plaintext {

using namespace ng::string::utils;

static bool is_comment(char c) {
    switch (c) {
        case ';':
        case '#':
            return true;
        default:
            return false;
    }
}

static bool is_section(const std::string& line, std::string& section) {
    if (line[0] == '[' && line.back() == ']') {
        section = line.substr(1, line.size() - 2);
        return true;
    }

    return false;
}

bool section_parser::get_bool_from_string_value(const std::string& value) {
    auto val = value;
    ng::string::utils::to_lower(val);
    return val == "on"     ? true
           : val == "yes"  ? true
           : val == "true" ? true
           : val == "1"    ? true
                           : false;
}

[[nodiscard]] bool ini_parser_base::load(const fs::path& ini_path) {
    using logging::error, logging::get_error_message;
    std::ifstream file(ini_path);

    const auto notify_error = [](const std::string& message) {
        error("unable to load the config file: {}", message);
        return false;
    };

    if (!file.is_open()) {
        return notify_error(get_error_message(errno));
    }

    /* reset sections */
    for (const auto& kvp : section_parser_map_) {
        kvp.second->reset();
    }

    std::string line;
    std::string current_section;
    std::string key;
    std::string value;
    while (std::getline(file, line)) {
        line = trim(line);

        if (line.empty() || is_comment(line[0])) {
            continue;
        }

        if (!is_section(line, current_section)) {
            if (!get_key(line, key) || !get_value(file, line, value)) {
                return notify_error("invalid config file.");
            }

            if (section_parser_map_.find(current_section) ==
                section_parser_map_.end()) {
                return notify_error(std::format("unknown config section '{}'",
                                                current_section));
            }

            section_parser_map_.at(current_section)->parse(key, value);
        }
    }

    m_loaded = true;
    return true;
}

[[nodiscard]] bool ini_parser_base::get_next_line(std::ifstream& file,
                                                  std::string& line) {
    while (std::getline(file, line)) {
        line = trim(line);

        if (line.empty() || line[0] == ';' || line[0] == '#') {
            continue;
        }

        return true;
    }
    return false;
}

[[nodiscard]] bool ini_parser_base::get_key(const std::string& line,
                                            std::string& key) {
    const auto end = line.find('=');
    if (end == std::string::npos) {
        return false;
    }

    key = trim(line.substr(0, end));

    return true;
}

[[nodiscard]] bool ini_parser_base::get_value(std::ifstream& file,
                                              const std::string& line,
                                              std::string& value) {
    const auto start = line.find('=') + 1;
    if (start == std::string::npos) {
        return false;
    }

    value = line.substr(start);
    value = handle_multiline_values(file, value);

    return true;
}

[[nodiscard]] std::string ini_parser_base::handle_multiline_values(
    std::ifstream& file, std::string& value) {
    std::string line;
    while (value.back() == '\\' && get_next_line(file, line)) {
        value.pop_back();
        value += line;
    }

    value = handle_escapes(trim(value));

    return value;
}

[[nodiscard]] std::string ini_parser_base::handle_escapes(
    const std::string& value) {
    std::ostringstream stream;

    bool in_escape_sequence = false;
    for (const auto& c : value) {
        if (in_escape_sequence) {
            switch (c) {
                case 'r':
                    stream << '\r';
                    break;
                case 'n':
                    stream << '\n';
                    break;
                case 't':
                    stream << '\t';
                    break;
                case '\\':
                    stream << '\\';
                    break;
                default:
                    stream << c;
                    break;
            }
            in_escape_sequence = false;
            continue;
        }

        if (c == '\\') {
            in_escape_sequence = true;
            continue;
        }

        stream << c;
    }

    if (in_escape_sequence) {
        stream << '\\';
    }

    return stream.str();
}

}  // namespace ng::plaintext
