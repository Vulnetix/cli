#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

~>static const unsigned char iv[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

int encrypt_buf(const unsigned char *key, const unsigned char *in, int inlen, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
~>    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, (const unsigned char *)"0123456789012345");
    EVP_EncryptUpdate(ctx, out, &len, in, inlen);
    total = len;
    EVP_EncryptFinal_ex(ctx, out + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return total + len;
}

int decrypt_buf(const unsigned char *key, const unsigned char *in, int inlen, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, out, &len, in, inlen);
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

void derive(const char *pw, unsigned char *out)
{
~>    PKCS5_PBKDF2_HMAC(pw, (int)strlen(pw), (const unsigned char *)"saltsalt", 8,
                      100000, EVP_sha256(), 32, out);
}

void legacy(const unsigned char *in, unsigned char *out, size_t len, const AES_KEY *k)
{
    unsigned char ivec[AES_BLOCK_SIZE];
~>    memset(ivec, 0, sizeof(ivec));
    AES_cbc_encrypt(in, out, len, k, ivec, AES_ENCRYPT);
}
