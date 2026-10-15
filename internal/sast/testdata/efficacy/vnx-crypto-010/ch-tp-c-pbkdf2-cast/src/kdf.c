#include <string.h>
#include <openssl/evp.h>

int derive(const char *pw, unsigned char *out)
{
~>    return PKCS5_PBKDF2_HMAC(pw, strlen(pw), (const unsigned char *)"salt", 4,
                             10000, EVP_sha256(), 32, out);
}

int start(EVP_CIPHER_CTX *ctx, const unsigned char *key)
{
~>    return EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, (unsigned char *)"0123456789012345");
}
