#include <stdio.h>
#include <stdlib.h>

/* Never write: buf = malloc(atoi(argv[1]) * sizeof(int)); use calloc. */
// p = malloc(ntohl(x) * 8);
static const char *hint = "malloc(atoi(s) * sizeof(int)) overflows";

int main(int argc, char **argv) {
    int n = atoi(argv[1]);
    printf("%s %d\n", hint, n * 2);
    return 0;
}
