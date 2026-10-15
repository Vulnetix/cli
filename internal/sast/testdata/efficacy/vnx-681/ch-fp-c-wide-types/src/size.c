#include <stdio.h>
#include <string.h>
#include <unistd.h>

long sizes(FILE *fp, int fd, const char *s)
{
    size_t len = strlen(s);
    long pos = ftell(fp);
    off_t o = lseek(fd, 0, SEEK_CUR);
    int n = strlen(s);
    ssize_t got = read(fd, (void *)s, 4);
    return pos + len + o + n + got;
}
