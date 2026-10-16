#include <string.h>
#include <openssl/evp.h>
#include "blob.h"

int blob_encrypt(const unsigned char *key, const unsigned char *in, int inlen,
                 unsigned char *out, int *outlen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    int len = 0;

~>    memset(iv, 0, sizeof(iv));
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
        goto fail;
    if (EVP_EncryptUpdate(ctx, out, &len, in, inlen) != 1)
        goto fail;
    *outlen = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    *outlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
fail:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
