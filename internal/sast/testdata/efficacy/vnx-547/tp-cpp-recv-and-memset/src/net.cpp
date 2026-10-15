#include <sys/socket.h>
#include <cstring>

void Session::readKey(int sock) {
    uint8_t key[32];
~>    std::memset(key, 0, 32);
~>    recv(sock, key, 32, 0);
}
