#include <string>
#include "nuggit-config.h"

void ng::nuggit_section::parse(const std::string& key,
                               const std::string& value) {
    if (key == "TCPPort") {
        m_tcp_port = std::stoi(value);
    } else if (key == "UDPPort") {
        m_udp_port = std::stoi(value);
    } else if (key == "ChatServer") {
        m_chat_server = get_bool_from_string_value(value);
    }
}
