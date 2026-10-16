#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

namespace net {

SOCKET OpenListener(const std::string& port)
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* result = nullptr;
    if (getaddrinfo(nullptr, port.c_str(), &hints, &result) != 0) {
        throw std::runtime_error("getaddrinfo failed");
    }

    SOCKET listenSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSock == INVALID_SOCKET) {
        freeaddrinfo(result);
        throw std::runtime_error("socket failed");
    }

    BOOL reuse = TRUE;
~>    if (setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse)) == SOCKET_ERROR) {
        closesocket(listenSock);
        freeaddrinfo(result);
        throw std::runtime_error("setsockopt failed");
    }

    if (bind(listenSock, result->ai_addr, static_cast<int>(result->ai_addrlen)) == SOCKET_ERROR) {
        closesocket(listenSock);
        freeaddrinfo(result);
        throw std::runtime_error("bind failed");
    }
    freeaddrinfo(result);
    listen(listenSock, SOMAXCONN);
    return listenSock;
}

}  // namespace net
