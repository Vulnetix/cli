#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

int check_password(const char *password, const char *expected)
{
    size_t len = strlen(password);
    if (len != strlen(expected))
        return 0;
    unsigned int seed;
    getrandom(&seed, sizeof seed, 0);
    srand(seed);
    return memcmp(password, expected, len) == 0;
}
