#include <stdio.h>
#include <string.h>
#include <unistd.h>

int is_png(FILE *f)
{
    unsigned char hdr[8];
    if (fread(hdr, 1, sizeof(hdr), f) != sizeof(hdr))
        return 0;
    return memcmp(hdr, "\x89PNG\r\n\x1a\n", 8) == 0;
}

void relay(int in, int out)
{
    char buf[4096];
    ssize_t n = read(in, buf, sizeof(buf));
    if (n > 0)
        write(out, buf, (size_t)n);
}

char *dup_str(const char *src)
{
    size_t len = strlen(src) + 1;
    char *dst = malloc(len);
    memcpy(dst, src, len);
    return dst;
}

void show_link(const char *p)
{
    char target[256];
    ssize_t n = readlink(p, target, sizeof(target) - 1);
    if (n < 0)
        return;
    target[n] = '\0';
    printf("%s\n", target);
}
