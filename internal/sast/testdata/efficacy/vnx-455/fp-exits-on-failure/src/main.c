#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialisation failed\n");
        exit(EXIT_FAILURE);
    }
    if (crypto_init(&ctx) != 0) {
        perror("crypto_init");
        return -1;
    }
    if (!subsystem_init())
        abort();
    if (net_setup() < 0) {
        log_error("net setup failed");
        goto fail;
    }
    return 0;
fail:
    return 1;
}
