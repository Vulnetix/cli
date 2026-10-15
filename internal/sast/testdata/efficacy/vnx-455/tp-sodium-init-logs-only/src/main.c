#include <stdio.h>
#include <sodium.h>

int main(void)
{
~>    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialisation failed\n");
    }
    return run_server();
}
