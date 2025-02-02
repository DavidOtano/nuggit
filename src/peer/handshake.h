#ifndef NG_HANDSHAKE_H
#define NG_HANDSHAKE_H

#include <socket.h>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>
#include <timer.h>
#include "wpn-util.h"
#include "../nuggit-service.h"

namespace ng::wpn::peer {

#ifndef NG_HANDSHAKE_SERVER_DEFAULT_PORT
#define NG_HANDSHAKE_SERVER_DEFAULT_PORT 4
#endif

struct handshake_context_t {
    net::tcp_socket s;
    uint32_t up_key, down_key;
    uint16_t local, remote;
    uint8_t local_block[16], remote_block[16];
    int sent, received;
    bool complete;
    timer timeout;
    std::string ip;

    bool is_server() const { return util::is_server_type(local); }
    bool valid_remote() const { return util::is_valid_type(remote); }
};

class peer_receiver {
public:
    virtual void accept(
        const std::unique_ptr<handshake_context_t>& context) = 0;
};

class handshake_server : public ng_service {
public:
    handshake_server(std::chrono::seconds timeout)
        : m_timeout(timeout), m_socket() {}
    bool add_receiver(uint16_t peer_type,
                      std::shared_ptr<peer_receiver> receiver);
    bool init();
    bool process() override;
    void set_port(uint16_t port) { m_port = port; }

private:
    void enqueue(SOCKET s);
    bool process_internal(const std::unique_ptr<handshake_context_t>& context);
    uint16_t m_port = NG_HANDSHAKE_SERVER_DEFAULT_PORT;
    std::chrono::seconds m_timeout;
    std::map<uint16_t, std::shared_ptr<peer_receiver>> m_receivers;
    net::tcp_socket m_socket;
    std::vector<std::unique_ptr<handshake_context_t>> m_pending = {};
};

}  // namespace ng::wpn::peer

#endif
