#include <stdio.h>
#include <sodium.h>

int crypto_box_setup(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return -1;
    }
    return 0;
}
