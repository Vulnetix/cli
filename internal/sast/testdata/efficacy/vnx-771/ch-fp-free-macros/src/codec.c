#include <stdlib.h>
#include <openssl/crypto.h>

#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)

void cycle(void)
{
    unsigned char *key = OPENSSL_malloc(32);
    use_key(key);
    OPENSSL_free(key);
    key = OPENSSL_malloc(64);
    use_key(key);
    OPENSSL_free(key);

    char *tmp = malloc(16);
    SAFE_FREE(tmp);
    tmp = malloc(32);
    SAFE_FREE(tmp);
    printf("p = malloc(1); p = malloc(2);\n");
}
