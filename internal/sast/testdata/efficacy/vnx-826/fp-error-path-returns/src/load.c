#include <stdio.h>
#include <unistd.h>

int load_config(const char *path, char *buf, size_t len)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    if (ftell(fp) > (long)len) { fclose(fp); return -2; }
    rewind(fp);
    size_t got = fread(buf, 1, len, fp);
    fclose(fp);
    return (int)got;
}

int send_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            close(fd);
            goto fail;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
fail:
    return -1;
}
