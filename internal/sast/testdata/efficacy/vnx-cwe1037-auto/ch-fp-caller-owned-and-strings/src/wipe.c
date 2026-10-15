#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void wipe_caller(char *key, size_t n)
{
    memset(key, 0, n);
}

void log_it(char *secret)
{
    printf("memset(secret, 0, n); free(secret);\n");
    /* memset(secret, 0, n); */
    explicit_bzero(secret, strlen(secret));
    free(secret);
}
