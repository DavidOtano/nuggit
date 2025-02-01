#ifndef NG_INI_PARSER_H
#define NG_INI_PARSER_H

#include <map>
#include <fstream>
#include <filesystem>

namespace ng::plaintext {
namespace fs = std::filesystem;

class ini_parser_exception : public std::runtime_error {
public:
    explicit ini_parser_exception(const std::string& message)
        : std::runtime_error(message) {}
};

class section_parser {
public:
    virtual void parse(const std::string& key, const std::string& value) = 0;
    virtual void reset() = 0;

protected:
    static bool get_bool_from_string_value(const std::string& value);
};

class ini_parser_base {
public:
    using section_parser_map_t = std::map<std::string, section_parser*>;
    ini_parser_base() noexcept : m_loaded(false) {}
    ini_parser_base(section_parser_map_t& section_parser_map) noexcept
        : section_parser_map_(std::move(section_parser_map)), m_loaded(false) {}
    ini_parser_base(ini_parser_base& parser) noexcept
        : section_parser_map_(std::move(parser.section_parser_map_)),
          m_loaded(false) {}
    ini_parser_base(ini_parser_base&& parser) noexcept
        : section_parser_map_(std::move(parser.section_parser_map_)),
          m_loaded(false) {}
    [[nodiscard]] virtual bool load(const fs::path& ini_path);
    [[nodiscard]] bool loaded() const { return m_loaded; }

protected:
    [[nodiscard]] static bool get_next_line(std::ifstream& file,
                                            std::string& line);
    [[nodiscard]] static bool get_key(const std::string& line,
                                      std::string& key);
    [[nodiscard]] static bool get_value(std::ifstream& file,
                                        const std::string& line,
                                        std::string& value);
    [[nodiscard]] static std::string handle_multiline_values(
        std::ifstream& file, std::string& value);
    [[nodiscard]] static std::string handle_escapes(const std::string& value);
    section_parser_map_t section_parser_map_;
    bool m_loaded;
};

}  // namespace ng::plaintext

#endif
