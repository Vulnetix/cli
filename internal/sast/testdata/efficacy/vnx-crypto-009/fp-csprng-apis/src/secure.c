#include <openssl/rand.h>
#include <sodium.h>
#include <stdlib.h>
#include <sys/random.h>

static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";

void generate_session_token(char *token, size_t n)
{
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1) abort();
    for (size_t i = 0; i + 1 < n && i < 32; i++)
        token[i] = alphabet[raw[i] % 36];
}

void make_nonce(unsigned char nonce[24], unsigned char key[32])
{
    randombytes_buf(nonce, 24);
    arc4random_buf(key, 32);
    if (getrandom(key, 32, 0) != 32) abort();
}

void make_otp(char *otp)
{
    otp[0] = '0' + arc4random_uniform(10);
}
