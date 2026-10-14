#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Ordinary non-security uses of rand(): sampling, jitter, test data. */
void evict_sample(struct dict *d, int n)
{
    srand(time(NULL) ^ getpid());
    int idx = rand() % n;
    double r = (double) rand() / RAND_MAX;
    usleep(1000 + rand() % 500);
    char *key = stringFromLongLong(rand() % n);
    uint64_t seed = (uint64_t) rand() | (uint64_t) rand() << 32;
    int token_count = rand() % 5;
    long session_timeout_ms = 1000 + random() % 250;
    entries[idx].key = key;
}

dictEntry *dictGetRandomKey(dict *d)
{
    unsigned long h = random() & d->sizemask;
    return d->table[h];
}

void shuffle(int *a, int n)
{
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int t = a[i]; a[i] = a[j]; a[j] = t;
    }
}
