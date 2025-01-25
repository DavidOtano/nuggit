#include <cstdlib>
#include <memory>
#include "handshake.h"
#if defined(_WIN32) || defined(_WIN64)
#include <winerror.h>
#include <winsock2.h>
#endif
#include "logging.h"
#include "../crypt/wpn_crypt.h"
#include "peer_types.h"
#include "socket.h"

namespace ng::wpn::peer {

using namespace wpn::crypt::tcp;

using logging::info, logging::error, logging::get_error_message;

bool handshake_server::add_receiver(uint16_t peer_type,
                                    std::shared_ptr<peer_receiver> receiver) {
    if (m_receivers.find(peer_type) != m_receivers.end()) {
        error("a receiver for peer type ({}) has already been registered...",
              peer_type);
        return false;
    }

    m_receivers[peer_type] = receiver;
    return true;
}

bool handshake_server::init() {
    if (!m_socket.is_valid()) {
        error("socket initialization failed: {}",
              get_error_message(WSAGetLastError()));
        return false;
    }

    if (!m_socket.bind("0.0.0.0", m_port)) {
        error("unable to bind to port {}: {}", m_port,
              get_error_message(WSAGetLastError()));
        return false;
    }

    if (!m_socket.listen(25)) {
        error("unable to listen on port {}: {}", m_port,
              get_error_message(WSAGetLastError()));
        return false;
    }

    if (!m_socket.mode(false)) {
        error("unable to set blocking mode: {}",
              get_error_message(WSAGetLastError()));
        return false;
    }

    info("handshake server started! listening for clients on port {}...",
         m_port);

    return true;
}

bool handshake_server::process() {
    auto s = m_socket.accept();
    if (s != INVALID_SOCKET) {
        enqueue(s);
    }

    /* handle timeouts */
    std::erase_if(m_pending, [](const auto& context) {
        auto result = context->timeout.has_elapsed();
        if (result) {
            info("{} -> handshake exceeded the timeout period.", context->ip);
        }
        return result;
    });

    /* handle failed handshakes */
    auto self = this;
    std::erase_if(m_pending, [self](auto& context) {
        return !self->process_internal(context);
    });

    for (auto& context : m_pending) {
        if (!context->complete) {
            continue;
        }

        info("{} -> handshake accepted.", context->ip);
        auto receiver = m_receivers[context->local];
        receiver->accept(context);
    }

    /* remove completed handshakes from the pending queue */
    std::erase_if(m_pending,
                  [](const auto& context) { return context->complete; });

    return true;
}

void handshake_server::enqueue(SOCKET s) {
    net::tcp_socket sock = s;
    if (!sock.mode(false)) {
        sock.close();
        return;
    }

    auto context = std::make_shared<handshake_context_t>();
    context->timeout = m_timeout;
    context->s = sock;
    context->sent = 0;
    context->received = 0;
    context->remote = 0;
    context->local = 0;
    context->ip = sock.remote_ip();
    m_pending.push_back(context);
    info("{} -> initiating handshake...", context->ip);
}

bool handshake_server::process_internal(
    std::shared_ptr<handshake_context_t>& context) {
    static char hdr = 0x31;

    auto close_and_exit = [context](const std::string& message) {
        error("({}) handshake failed. {}: {}", context->ip, message,
              get_error_message(WSAGetLastError()));
        context->s.close();
        return false;
    };

    if (context->sent < 1) {
        auto res = context->s.send(&hdr, 1, 0);
        if (res == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                return close_and_exit("unable to send header byte");
            }
        } else {
            context->sent += res;
        }
    }

    if (context->received < 16) {
        auto res = context->s.receive(
            reinterpret_cast<char*>(context->remote_block + context->received),
            16 - context->received, 0);

        if (res == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                return close_and_exit("unable to receive key block");
            }
        } else if (res == 0) {
            return close_and_exit("unable to receive key block");
        } else {
            context->received += res;
        }
    }

    if (context->received == 16) {
        if (!context->local) {
            context->remote = get_crypt_key_id(context->remote_block);

            switch (context->remote) {
                case NG_PRIMARY_CLIENT:
                    context->local = NG_PRIMARY_SERVER;
                    break;
                case NG_CHAT_CLIENT:
                    context->local = NG_CHAT_SERVER;
                    break;
                case NG_SECONDARY_CLIENT:
                    context->local = NG_SECONDARY_SERVER;
                    break;
                default:
                    return close_and_exit(
                        std::format("unsupported client type ({}) received",
                                    context->remote));
            }

            if (m_receivers.find(context->local) == m_receivers.end()) {
                return close_and_exit(
                    std::format("unregistered peer receiver type ({}) received",
                                context->local));
            }

            create_crypt_key_id(context->local, context->local_block);
            get_crypt_key(context->local_block, &context->down_key,
                          &context->up_key);
        }

        if (context->sent < 17) {
            auto res =
                context->s.send(reinterpret_cast<char*>(context->local_block +
                                                        (context->sent - 1)),
                                17 - context->sent, 0);

            if (res == SOCKET_ERROR) {
                if (WSAGetLastError() != WSAEWOULDBLOCK) {
                    return close_and_exit("unable to send key block");
                }
            } else {
                context->sent += res;
            }
        }
    }

    context->complete = context->received == 16 && context->sent == 17;
    return true;
}

}  // namespace ng::wpn::peer
