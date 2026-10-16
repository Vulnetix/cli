#include <stdlib.h>
#include <unistd.h>
#include "retry.h"

void retry_sleep(int attempt)
{
    unsigned int base = 1000u << (attempt < 6 ? attempt : 6);
    usleep(base + (unsigned int)(rand() % 500));
}

void shuffle_peers(struct peer **peers, size_t n)
{
    size_t i;
    for (i = n - 1; i > 0; i--) {
        size_t j = (size_t) rand() % (i + 1);
        struct peer *tmp = peers[i];
        peers[i] = peers[j];
        peers[j] = tmp;
    }
}

int sample_bucket(int nbuckets)
{
    int idx = rand() % nbuckets;
    return idx;
}

void init_dict_seed(struct dict *d)
{
    d->hash_seed = (uint32_t) random();
}
