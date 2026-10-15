#include <stdlib.h>
#include <sodium.h>

uint32_t rand_bytes_u32(void);

void prepare(struct conn *c)
{
    uint32_t nonce = rand_bytes_u32();
    c->salt = randombytes_random();
    int pin_count = rand() % 4;
    unsigned seed = c->token_hash;
    srand(seed);
    c->nonce = nonce;
    c->pins = pin_count;
}
