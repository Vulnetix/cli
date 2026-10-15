#include <stdlib.h>
#include <string.h>

void fill(size_t n) {
    unsigned char *block = malloc(n);
    size_t half = n / 2;
~>    memset(block, 0, half);
}
