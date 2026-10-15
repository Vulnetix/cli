#include <strings.h>
#include <stdlib.h>

void card_close(char *pin, size_t n)
{
    char *masterSecret = malloc(64);
    load_master(masterSecret);
~>    bzero(masterSecret, 64);
    OPENSSL_free(masterSecret);
~>    memset(pin, '\0', n);
    free(pin);
}
