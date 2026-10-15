#include <stdlib.h>
#include <time.h>
#include <stdint.h>

struct handshake {
    uint32_t client_nonce;
    uint32_t server_nonce;
};

void handshake_init(struct handshake *hs)
{
    srand((unsigned)time(NULL));
~>    hs->client_nonce = (uint32_t)rand();
~>    hs->server_nonce = rand() ^ (rand() << 16);
}
