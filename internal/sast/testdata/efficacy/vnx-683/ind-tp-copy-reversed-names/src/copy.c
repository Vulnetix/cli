#include <string.h>

void relay(char *src, char *dst, size_t n, char *input, char *output)
{
~>    memcpy(src, dst, n);
~>    strcat(input, output);
}
