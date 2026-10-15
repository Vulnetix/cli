#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

void copy(int in, int out)
{
    char buf[4096];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0)
        write(out, buf, (size_t)n);
}

void put_flag(int fd)
{
    char c = 'Y';
    write(fd, &c, 1);
    uint8_t tag = 7;
    write(fd, &tag, sizeof(tag));
    unsigned char b = 0;
    read(fd, &b, sizeof b);
    fwrite(&c, sizeof(char), 1, stdout);
}

void dump(FILE *fp, const unsigned char *data, size_t len)
{
    fwrite(data, 1, len, fp);
}
