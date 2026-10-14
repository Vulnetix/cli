#include <openssl/evp.h>
#include <openssl/rand.h>

int encrypt_random(const unsigned char *key, const unsigned char *in, int inlen, unsigned char *out, unsigned char *iv_out)
{
    unsigned char iv[16] = {0};
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        return -1;
    memcpy(iv_out, iv, sizeof(iv));
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

int decrypt_with(const unsigned char *key, const unsigned char *iv, const unsigned char *in, int inlen, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &len, in, inlen);
    EVP_CIPHER_CTX_free(ctx);
    return len;
}
