#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void copy_name(char *dst, size_t dstlen, const char *src)
{
    strncpy(dst, src, dstlen);
    dst[dstlen - 1] = '\0';
}

void copy_err(char *errbuf, size_t size, const char *err)
{
    strncpy(errbuf, err, size - 1);
    errbuf[size - 1] = 0;
}

void copy_fmt(char *form, const char *start, const char *p)
{
    strncpy(form, start, p - start + 1);
    form += p - start + 1;
    *form = '\0';
}

int read_num(int fd)
{
    char buf[32];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    return atoi(buf);
}

char *dup_term(const char *tok)
{
    size_t len = strlen(tok);
    char *out = malloc(len + 1);
    memcpy(out, tok, strlen(tok));
    out[len] = '\0';
    return out;
}
