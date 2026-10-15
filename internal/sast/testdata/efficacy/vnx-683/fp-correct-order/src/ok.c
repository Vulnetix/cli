#include <stdio.h>
#include <string.h>

void ok(char *dst, const char *src, size_t n, FILE *fp, char *buf) {
    memcpy(dst, src, n);
    memmove(dst, src, n);
    strcpy(dst, src);
    strncpy(dest, source, n);
    memset(buf, 0, n);
    memset(buf, 0, 0);
    memset(buf, '\0', sizeof(buf));
    fputs(msg, stderr);
    fwrite(buf, 1, n, fp);
    fread(buf, 1, n, stdin);
    fputc('x', fp);
    memcpy(to, from, n);
    memcpy(src_copy, src, n);
}
