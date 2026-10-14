#include <stdlib.h>
#include <stdint.h>

struct handshake {
    uint32_t nonce;
    uint8_t salt[8];
};

void prepare(struct handshake *h, unsigned short xsubi[3])
{
~>    long v = nrand48(xsubi);
    h->nonce = (uint32_t) v ^ 0x5a5a5a5aU;

    for (int i = 0; i < 8; i++) {
~>        int r = rand_r(&seed_state);
        h->salt[i] = (uint8_t) r;
    }
}

uint32_t challenge_value;

void refresh(void)
{
~>    challenge_value = (uint32_t)(drand48() * 4294967295.0);
}
