#include <stdio.h>
#include <string.h>

void io(FILE *out, char *dst, const char *src, char *saved_src, size_t n, int c)
{
    memset(dst, ' ', n);
    memset(dst, 0, sizeof(*dst));
    memcpy(dst, src, n);
    memcpy(saved_src, src, n);
    fputs("ok\n", out);
    fwrite(dst, 1, n, out);
    fputc(c, out);
    putc(c, stdout);
}
