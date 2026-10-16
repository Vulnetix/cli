#include <stdio.h>
#include <string.h>

void ok(char *dst, const char *src, size_t n, FILE *fp, char *key)
{
    memset(key, 0, 32);
    memset(dst, 0, 0);
    memcpy(dst, src, n);
    strcpy(dst, src);
    fputs("hello", stderr);
    fwrite(src, 1, n, fp);
    fgets(dst, (int)n, stdin);
}
