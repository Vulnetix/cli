#include <string.h>

void copy(char *dst, const char *src, size_t n, char *dest_buf, char *source) {
~>    memcpy(src, dst, n);
~>    memmove(source, dest_buf, n);
~>    strcpy(src, dst);
~>    strncpy(s->src, s->dst, n);
~>    strcat(input, output);
}
