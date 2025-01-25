#ifndef NG_SOCKET_H
#define NG_SOCKET_H

#include <socket-defs.h>
#include <string>

namespace ng::net {

class tcp_socket {
public:
    tcp_socket() noexcept {
        initialize();
        m_closed = false;
        m_blocking = true;
        m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }

    tcp_socket(SOCKET s) noexcept : m_socket(s), m_closed(false), m_blocking(true) {}
    tcp_socket(tcp_socket&& s) noexcept : tcp_socket(s.m_socket) {}
    tcp_socket(tcp_socket& s) noexcept : m_socket(s.m_socket), m_closed(s.m_closed), m_blocking(true) {}

    [[nodiscard]] virtual bool is_valid() const {
        return m_socket != INVALID_SOCKET;
    }

    [[nodiscard]] virtual int send(const char* buf, int len, int flags) const {
        return ::send(m_socket, buf, len, flags);
    }

    [[nodiscard]] virtual int receive(char* buf, int len, int flags) const {
        return ::recv(m_socket, buf, len, flags);
    }

    [[nodiscard]] virtual bool bind(const std::string& ip,
                                    unsigned short port) const {
        in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
            return false;
        }

        SOCKADDR_IN sin;
        sin.sin_addr = addr;
        sin.sin_port = htons(port);
        sin.sin_family = AF_INET;

        return ::bind(m_socket, (struct sockaddr*)&sin, sizeof(SOCKADDR_IN)) !=
               SOCKET_ERROR;
    }

    [[nodiscard]] virtual bool listen(int backlog) const {
        return ::listen(m_socket, backlog) != SOCKET_ERROR;
    }

    [[nodiscard]] virtual bool mode(bool blocking = true) {
#if defined(_WIN32) || defined(_WIN64)
        unsigned long arg = blocking ? 0 : 1;
        auto result = ::ioctlsocket(m_socket, FIONBIO, &arg) != SOCKET_ERROR;
        if (result) m_blocking = blocking;
#else
        int flags = fcntl(m_socket, F_GETFL, 0);
        if (flags == SOCKET_ERROR) return false;

        if (blocking) {
            flags &= ~O_NONBLOCK;
        } else {
            flags |= O_NONBLOCK;
        }

        auto result = fcntl(m_socket, F_SETFL, flags) != SOCKET_ERROR;
        if (result) m_blocking = blocking;
#endif
        return result;
    }

    [[nodiscard]] virtual bool shutdown(int how = SHUT_RD) const {
        return ::shutdown(m_socket, how) != SOCKET_ERROR;
    }

    virtual bool close() {
        if (m_closed || m_socket == INVALID_SOCKET) return 0;
        bool result = m_closed = ::closesocket(m_socket) != SOCKET_ERROR;
        return result;
    }

    [[nodiscard]] virtual SOCKET accept() {
        return ::accept(m_socket, nullptr, nullptr);
    }

    [[nodiscard]] virtual const std::string& remote_ip() {
        if (!m_remote_ip.empty()) {
            return m_remote_ip;
        }

        SOCKADDR_IN sin = {};
        socklen_t sin_size;
        sin_size = sizeof(struct sockaddr_in);

        if (::getpeername(m_socket, (struct sockaddr*)&sin, &sin_size) ==
            SOCKET_ERROR) {
            return m_remote_ip;
        }

        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &sin.sin_addr, ip, INET_ADDRSTRLEN);
        m_remote_ip = ip;
        return m_remote_ip;
    }

    virtual operator bool() const { return is_valid(); }
    virtual operator SOCKET() const { return m_socket; }

    virtual tcp_socket& operator=(tcp_socket& other) {
        m_socket = other.m_socket;
        m_closed = other.m_closed;
        m_blocking = other.m_blocking;
        return *this;
    }

    virtual tcp_socket&& operator=(tcp_socket&& other) noexcept {
        m_socket = other.m_socket;
        m_closed = other.m_closed;
        m_blocking = other.m_blocking;
        return std::forward<tcp_socket>(*this);
    }

protected:
    static void initialize() {
#if defined(_WIN32) || defined(_WIN64)
        static bool initialized = false;
        if (initialized) return;

        WSADATA data;
        initialized = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
#endif
    }

    SOCKET m_socket;
    bool m_closed;
    bool m_blocking;
    std::string m_remote_ip = "";
};

}  // namespace ng::net

#endif
