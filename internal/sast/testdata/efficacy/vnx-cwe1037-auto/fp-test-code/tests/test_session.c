#include <stdlib.h>
#include <string.h>

static void test_destroy(void)
{
    unsigned char *key = malloc(32);
    memset(key, 0, 32);
    free(key);
}
