#ifndef NG_CHAT_USER_H
#define NG_CHAT_USER_H

#include <chrono>
#include <cstdint>
#include <socket.h>
#include <timer.h>
#include <memory>
#include "../proto/packet.h"
#include "../peer/handshake.h"
#include "spam-control.h"

namespace ng::wpn::chat {

using namespace wpn::proto;

struct primary_info_t {
    primary_info_t() : ip(0), port(0) {}
    uint32_t ip;
    uint16_t port;
};

struct user_info_t {
    user_info_t()
        : channelname(""), username(""), line_type(0), files(0), primary() {}
    std::string channelname;
    std::string username;
    uint16_t line_type;
    uint32_t files;
    primary_info_t primary;
};

struct tcp_keys_t {
    tcp_keys_t() : up(0), down(0) {}
    uint32_t up, down;
};

struct user_status_t {
    user_status_t() : logged_in(false), login_timeout() {}
    bool logged_in;
    timer login_timeout;
};

struct chat_user_context_t {
    chat_user_context_t(const net::tcp_socket& socket)
        : info(),
          keys(),
          status(),
          s(socket),
          recv_buffer(),
          send_buffer(),
          is353(false),
          is_shutdown(false),
          disconnect_after(false),
          ping(false),
          created_at(std::chrono::high_resolution_clock::now()),
          is_hidden(false) {}

    chat_user_context_t(net::tcp_socket&& socket)
        : info(),
          keys(),
          status(),
          s(socket),
          recv_buffer(),
          send_buffer(),
          is353(false),
          is_shutdown(false),
          disconnect_after(false),
          ping(false),
          created_at(std::chrono::high_resolution_clock::now()),
          is_hidden(false) {}

    user_info_t info;
    tcp_keys_t keys;
    user_status_t status;
    net::tcp_socket s;
    packet_buffer_t recv_buffer;
    packet_buffer_t send_buffer;
    std::string ip;
    bool is353;
    bool is_shutdown;
    timer disconnect_after;
    timer ping;
    spam_control spam_ctrl;
    std::string access;
    std::string format;
    std::chrono::time_point<std::chrono::high_resolution_clock> created_at;
    bool is_hidden;

    bool has_access(char access_character) const {
        if (access_character != '+' && access_character != '@' &&
            access_character != 'b' && access.find('*') != std::string::npos) {
            return true;
        }
        return access.find(access_character) != std::string::npos;
    }

    uint8_t rank() const {
        return has_access('@') ? 1 : has_access('+') ? 2 : 0;
    }

    static std::unique_ptr<chat_user_context_t> from_handshake(
        const std::unique_ptr<peer::handshake_context_t>& context) {
        auto ret = std::make_unique<chat_user_context_t>(context->s);
        ret->keys.up = context->up_key;
        ret->keys.down = context->down_key;
        ret->ip = context->ip;
        return ret;
    }
};

}  // namespace ng::wpn::chat

#endif
