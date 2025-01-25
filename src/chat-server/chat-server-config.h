#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <vector>

#define section_parser_pair std::make_pair<std::string, section_parser*>

#include "../ini-parser.h"

namespace ng::config::chat_server {
using namespace ng::plaintext;

class chat_server_section : public section_parser {
public:
    chat_server_section() : m_limit(60) {}

    void parse(const std::string& key, const std::string& value);
    const std::vector<std::string>& channelnames() const {
        return m_channelnames;
    }
    const std::string topic() const { return m_topic; }
    const std::vector<std::string>& motd() const { return m_motd; }
    int limit() const { return m_limit; }
    bool show_chat_history() const { return m_show_chat_history; }
    const std::string& chat_history_header() const {
        return m_chat_history_header;
    }
    const std::string& chat_history_footer() const {
        return m_chat_history_footer;
    }

private:
    std::vector<std::string> m_channelnames;
    std::string m_topic;
    std::vector<std::string> m_motd;
    int m_limit;
    bool m_show_chat_history;
    std::string m_chat_history_header;
    std::string m_chat_history_footer;
};

class chat_server_login_section : public section_parser {
public:
    typedef struct {
        std::string password;
        std::string access;
        std::string format;
    } login_info;
    void parse(const std::string& key, const std::string& value);
    const std::vector<login_info>& logins() const { return m_logins; }
    const std::string& default_access() const { return m_default_access; }
    const std::string& default_format() const { return m_default_format; }
    bool with_password(const std::string& password, std::string& access,
                       std::string& format) const;

private:
    std::vector<login_info> m_logins;
    login_info m_current_login;
    std::string m_default_access;
    std::string m_default_format;
};

}  // namespace ng::config::chat_server

#endif
