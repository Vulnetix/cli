#include <openssl/evp.h>
#include <openssl/rand.h>
#include "seal.h"

int seal_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, unsigned char iv[16])
{
    if (RAND_bytes(iv, 16) != 1)
        return -1;
    return EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
}

int ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key)
{
    return EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
}

int ctx_reinit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv)
{
    return EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
}
