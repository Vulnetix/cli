#include <stdlib.h>
#include <time.h>
#include <sys/random.h>
#include <openssl/rand.h>
#include "token.h"

void app_init(void)
{
    srand((unsigned) time(NULL));
}

int generate_token(unsigned char *token, size_t len)
{
    if (getrandom(token, len, 0) != (ssize_t) len)
        return -1;
    return 0;
}

int make_nonce(unsigned char nonce[12])
{
    return RAND_bytes(nonce, 12) == 1 ? 0 : -1;
}

uint32_t new_session_id(void)
{
    return arc4random();
}
