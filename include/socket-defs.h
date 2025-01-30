#ifndef NG_SOCKET_DEFS_H
#define NG_SOCKET_DEFS_H

#include <cstdint>
#include <future>
#include <sstream>
#include <string>
#include <utility>
#if !defined(_WIN32) && !defined(_WIN64)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>

#define INVALID_SOCKET (~0)
#define SOCKET_ERROR (-1)
#define SOCKET int
#define WSAPoll poll
#define closesocket close
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 0
#endif
#define NG_INIT_SOCKET_LIB()
#define WSAEWOULDBLOCK EWOULDBLOCK
#define SOCKADDR_IN struct sockaddr_in
#define WSAGetLastError() errno
#ifndef NI_MAXHOST
#define NI_MAXHOST 1024
#endif
#else
#include <ws2tcpip.h>
#include <winsock2.h>
#include <windows.h>

#define NG_INIT_SOCKET_LIB()                    \
    ({                                          \
        WSADATA data;                           \
        WSAStartup(MAKEWORD(2, 2), &data) == 0; \
    })

#ifndef SHUT_RD
#define SHUT_RD 0
#endif

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR 2
#endif

#endif

static uint32_t ip_to_uint(const std::string& ip) {
    uint32_t ret = 0;
    inet_pton(AF_INET, ip.c_str(), &ret);
    return ret;
}

static void extract_ip_range(const std::string& ip_range, std::string& from,
                             std::string& to) {
    std::stringstream ss(ip_range);
    std::getline(ss, from, '-');
    std::getline(ss, to, '\0');

    const auto from_addr = ip_to_uint(from), to_addr = ip_to_uint(to);
    if (from_addr > to_addr) {
        std::swap(from, to);
    }
}

static std::future<std::string> resolve_hostname(const std::string& ip) {
    return std::async(std::launch::async, [&ip]() {
        std::string hostname;
        hostname.resize(NI_MAXHOST);

        SOCKADDR_IN sa;
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, &ip[0], &sa.sin_addr);
        getnameinfo((struct sockaddr*)&sa, sizeof sa, &hostname[0], NI_MAXHOST,
                    nullptr, 0, 0);
        hostname.resize(hostname.find('\0'));
        return hostname;
    });
}

#endif
