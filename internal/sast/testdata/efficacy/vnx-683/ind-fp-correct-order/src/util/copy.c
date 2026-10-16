#include <stdio.h>
#include <string.h>

void ok(char *dst, const char *src, size_t n, FILE *fp, char *buf)
{
    memset(buf, 0, n);
    memset(buf, 0, 0);
    memcpy(dst, src, n);
    strncpy(dst, src, n - 1);
    fputs(buf, stderr);
    fwrite(buf, 1, n, fp);
    fgets(buf, (int)n, stdin);
    fputc('\n', stdout);
}
