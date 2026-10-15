#include <openssl/evp.h>

int encrypt_block(const unsigned char *key, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, NULL)) {
~>        EVP_CIPHER_CTX_free(ctx);
        goto err;
    }
    EVP_EncryptFinal_ex(ctx, out, &len);
    EVP_CIPHER_CTX_free(ctx);
    return len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
