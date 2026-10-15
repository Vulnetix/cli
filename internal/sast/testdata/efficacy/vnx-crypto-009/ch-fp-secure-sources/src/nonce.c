#include <openssl/rand.h>
#include <sys/random.h>
#include <stdlib.h>

int make_nonce(unsigned char *nonce, size_t len)
{
    if (RAND_bytes(nonce, (int)len) != 1)
        return -1;
    return 0;
}

void session_token(unsigned char out[32])
{
    getrandom(out, 32, 0);
    uint32_t salt = arc4random();
    (void)salt;
}

void jitter_retry(void)
{
    int backoff_ms = 100 + rand() % 50;
    sleep_ms(backoff_ms);
}
