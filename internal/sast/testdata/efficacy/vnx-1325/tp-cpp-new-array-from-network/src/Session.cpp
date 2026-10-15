#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstdint>

void Session::readFrame(int fd) {
    uint32_t raw = 0;
    recv(fd, &raw, sizeof(raw), MSG_WAITALL);
    uint32_t len = ntohl(raw);
~>    char *payload = new char[len];
~>    void *copy = malloc(len + 1);
    recv(fd, payload, len, MSG_WAITALL);
    handle(payload, len);
    delete[] payload;
    free(copy);
}
