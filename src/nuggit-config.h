#ifndef NG_NUGGIT_CONFIG_H
#define NG_NUGGIT_CONFIG_H

#include "ini-parser.h"
#include "chat-server/chat-server-config.h"

namespace ng {

using namespace ng::plaintext;

class nuggit_section : public section_parser {
public:
    void parse(const std::string& key, const std::string& value) override;

    int tcp_port() const { return m_tcp_port; }
    int udp_port() const { return m_udp_port; }
    bool chat_server() const { return m_chat_server; }

private:
    int m_tcp_port = 6688;
    int m_udp_port = 6256;
    bool m_chat_server = true;
};

class nuggit_config_reader : public ini_parser_base {
public:
    nuggit_config_reader() : ini_parser_base() {
        section_parser_map_ = {
            section_parser_pair("nuggit", &m_nuggit_section),
            section_parser_pair("ChatServer", &m_chat_server_section),
            section_parser_pair("ChatServer::Logins",
                                &m_chat_server_login_section),
        };
    }

    const nuggit_section& nuggit() const { return m_nuggit_section; }
    const ng::config::chat_server::chat_server_section& chat_server() const {
        return m_chat_server_section;
    }
    const ng::config::chat_server::chat_server_login_section&
    chat_server_login() const {
        return m_chat_server_login_section;
    }

private:
    nuggit_section m_nuggit_section;
    ng::config::chat_server::chat_server_section m_chat_server_section;
    ng::config::chat_server::chat_server_login_section
        m_chat_server_login_section;
};

}  // namespace ng

#endif
