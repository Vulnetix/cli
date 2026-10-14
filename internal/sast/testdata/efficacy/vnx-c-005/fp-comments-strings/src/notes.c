#include <stdio.h>
#include <stdlib.h>

/* Never call malloc(atoi(arg) * size): the product can wrap. */
void usage(const char *arg)
{
    int n = atoi(arg);
    // malloc(n * sizeof(int)) would overflow for large n
    printf("malloc(n * sizeof(int)) with n=%d is refused\n", n);
}
