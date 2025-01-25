#include <format>
#include <string>
#include "chat-server-config.h"

void ng::config::chat_server::chat_server_section::parse(
    const std::string& key, const std::string& value) {
    if (key == "ChannelName") {
        m_channelnames.push_back(value);
    } else if (key == "Topic") {
        m_topic = value;
    } else if (key == "Motd") {
        m_motd.push_back(value);
    } else if (key == "Limit") {
        m_limit = std::stoi(value);
    } else if (key == "ShowChatHistoryOnEntry") {
        m_show_chat_history = get_bool_from_string_value(value);
    } else if (key == "ChatHistoryHeader") {
        m_chat_history_header = value;
    } else if (key == "ChatHistoryFooter") {
        m_chat_history_footer = value;
    } else {
        throw ini_parser_exception(std::format("invalid server key '{}'", key));
    }
}

void ng::config::chat_server::chat_server_login_section::parse(
    const std::string& key, const std::string& value) {
    if (key == "DefaultAccess") {
        m_default_access = value;
        return;
    } else if (key == "DefaultFormat") {
        m_default_format = value;
        return;
    } else if (key == "LoginPassword") {
        m_current_login.password = value;
    } else if (key == "LoginAccess") {
        m_current_login.access = value;
    } else if (key == "LoginFormat") {
        m_current_login.format = value;
    } else {
        throw ini_parser_exception(std::format("invalid login key '{}'", key));
    }

    if (!m_current_login.password.empty() && !m_current_login.access.empty() &&
        !m_current_login.format.empty()) {
        m_logins.push_back(m_current_login);
        m_current_login = {.password = "", .access = "", .format = ""};
    }
}

bool ng::config::chat_server::chat_server_login_section::with_password(
    const std::string& password, std::string& access,
    std::string& format) const {
    for (const auto& login : m_logins) {
        if (login.password == password) {
            access = login.access;
            format = login.format;
            return true;
        }
    }

    return false;
}
