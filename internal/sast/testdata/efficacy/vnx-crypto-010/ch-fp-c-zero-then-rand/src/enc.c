#include <openssl/evp.h>
#include <openssl/rand.h>

int encrypt_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, unsigned char *iv_out)
{
    unsigned char iv[16] = {0};
    if (RAND_bytes(iv, sizeof iv) != 1)
        return -1;
    memcpy(iv_out, iv, sizeof iv);
    return EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
}
