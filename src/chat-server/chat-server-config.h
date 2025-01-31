#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <vector>
#include <sstream>

#define section_parser_pair std::make_pair<std::string, section_parser*>

#include "../ini-parser.h"
#include "string-utils.h"

namespace ng::config::chat_server {
using namespace ng::plaintext;

class chat_server_section : public section_parser {
public:
    chat_server_section() : m_limit(60) {}

    void parse(const std::string& key, const std::string& value) override;
    void reset() override {
        m_channelnames.clear();
        m_topics.clear();
        m_motd.clear();
    }
    const std::vector<std::string>& channelnames() const {
        return m_channelnames;
    }
    const std::vector<std::string>& topics() const { return m_topics; }
    const std::vector<std::string>& motd() const { return m_motd; }
    int limit() const { return m_limit; }
    bool show_chat_history() const { return m_show_chat_history; }
    const std::string& chat_history_header() const {
        return m_chat_history_header;
    }
    const std::string& chat_history_footer() const {
        return m_chat_history_footer;
    }
    bool fancy_entry() const { return m_fancy_entry; }
    const std::string& fancy_entry_message() const {
        return m_fancy_entry_message;
    }
    const std::string& fancy_entry_message_ip() const {
        return m_fancy_entry_message_ip;
    }
    const std::string& private_message_recv_format() const {
        return m_private_message_recv_format;
    }
    const std::string& private_message_send_format() const {
        return m_private_message_send_format;
    }
    const std::string& opmsg_format() const { return m_opmsg_format; }
    bool rename_notification() const { return m_rename_notification; }
    const std::string& rename_notification_format() const {
        return m_rename_notification_format;
    }
    const std::string& external_ip_resolution_url() const {
        return m_external_ip_resolution_url;
    }
    bool resolve_countries() const { return m_resolve_countries; }
    const std::string& country_resolver_url() const {
        return m_country_resolver_url;
    }
    void set_topic(const std::string& topic, size_t topic_index) {
        while (topic_index > m_topics.size()) {
            m_topics.emplace_back();
        }

        m_topics[topic_index] = topic;
    }
    void set_motd(const std::string& motd) {
        m_motd.clear();
        add_motd(motd);
    }
    void add_motd(const std::string& motd) {
        using ng::string::utils::replace;
        auto copy = motd;
        replace(copy, "#\n#", "\n");
        replace(copy, "\\n", "\n");
        std::string line;
        std::stringstream ss(copy);
        while (std::getline(ss, line)) {
            m_motd.emplace_back(line);
        }
    }
    void set_limit(int limit) { m_limit = limit; }

private:
    std::vector<std::string> m_channelnames;
    std::vector<std::string> m_topics;
    std::vector<std::string> m_motd;
    int m_limit;
    bool m_show_chat_history;
    std::string m_chat_history_header;
    std::string m_chat_history_footer;
    bool m_fancy_entry;
    std::string m_fancy_entry_message;
    std::string m_fancy_entry_message_ip;
    std::string m_private_message_recv_format;
    std::string m_private_message_send_format;
    std::string m_opmsg_format;
    bool m_rename_notification;
    std::string m_rename_notification_format;
    std::string m_external_ip_resolution_url;
    bool m_resolve_countries;
    std::string m_country_resolver_url;
};

class chat_server_login_section : public section_parser {
public:
    typedef struct {
        std::string password;
        std::string access;
        std::string format;
    } login_info;
    void parse(const std::string& key, const std::string& value) override;
    void reset() override {
        m_logins.clear();
        m_current_login = {.password = "", .access = "", .format = ""};
    }

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
