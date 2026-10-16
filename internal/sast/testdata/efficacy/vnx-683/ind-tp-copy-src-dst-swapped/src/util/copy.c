#include <string.h>

void copy_block(char *dst, const char *src, size_t n)
{
~>    memcpy(src, dst, n);
}

void append_name(char *output, char *input)
{
~>    strcat(input, output);
}

void move_region(char *dest, char *source, size_t len)
{
~>    memmove(source, dest, len);
}
