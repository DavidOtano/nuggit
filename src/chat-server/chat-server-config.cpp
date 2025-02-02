#include <format>
#include <string>
#include "chat-server-config.h"

void ng::config::chat_server::chat_server_section::parse(
    const std::string& key, const std::string& value) {
    if (key == "ChannelName") {
        if (m_channelnames.size() == 3) {
            return;
        }
        m_channelnames.emplace_back(value);
    } else if (key == "Topic") {
        if (m_topics.size() == 3) {
            return;
        }
        m_topics.emplace_back(value);
    } else if (key == "Motd") {
        m_motd.emplace_back(value);
    } else if (key == "Limit") {
        m_limit = std::stoi(value);
    } else if (key == "ShowChatHistoryOnEntry") {
        m_show_chat_history = get_bool_from_string_value(value);
    } else if (key == "ChatHistoryHeader") {
        m_chat_history_header = value;
    } else if (key == "ChatHistoryFooter") {
        m_chat_history_footer = value;
    } else if (key == "ChatHistoryLength") {
        m_chat_history_length = std::stoi(value);

        if (m_chat_history_length < 0) {
            m_chat_history_length = 0;
        }
        if (m_chat_history_length > 100) {
            m_chat_history_length = 100;
        }
    } else if (key == "FancyEntry") {
        m_fancy_entry = get_bool_from_string_value(value);
    } else if (key == "FancyEntryMessage") {
        m_fancy_entry_message = value;
    } else if (key == "FancyEntryMessageIP") {
        m_fancy_entry_message_ip = value;
    } else if (key == "PrivateMessageRecvFormat") {
        m_private_message_recv_format = value;
    } else if (key == "PrivateMessageSendFormat") {
        m_private_message_send_format = value;
    } else if (key == "OpMsgFormat") {
        m_opmsg_format = value;
    } else if (key == "RenameNotification") {
        m_rename_notification = get_bool_from_string_value(value);
    } else if (key == "RenameNotificationFormat") {
        m_rename_notification_format = value;
    } else if (key == "ExternalIPResolutionUrl") {
        m_external_ip_resolution_url = value;
    } else if (key == "ResolveCountries") {
        m_resolve_countries = get_bool_from_string_value(value);
    } else if (key == "CountryResolverUrl") {
        m_country_resolver_url = value;
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
        m_logins.emplace_back(m_current_login);
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
