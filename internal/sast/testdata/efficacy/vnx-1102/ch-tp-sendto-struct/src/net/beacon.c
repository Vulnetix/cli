#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct beacon {
    uint32_t node_id;
    uint16_t port;
    double load;
};

int announce(int sock, const struct sockaddr_in *peer, uint32_t id, double load)
{
    struct beacon b;
    memset(&b, 0, sizeof(b));
    b.node_id = id;
    b.port = 7000;
    b.load = load;
~>    return (int)sendto(sock, &b, sizeof(b), 0,
                       (const struct sockaddr *)peer, sizeof(*peer));
}
