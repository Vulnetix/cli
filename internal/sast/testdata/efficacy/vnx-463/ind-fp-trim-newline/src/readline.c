#include <stdio.h>
#include <string.h>

int read_name(FILE *fp, char *buf, size_t cap)
{
    size_t n;

    if (!fgets(buf, (int)cap, fp))
        return -1;
    n = strlen(buf);
    if (n && buf[n - 1] == '\n')
        buf[n - 1] = '\0';
    buf[strlen(buf)] = '\0';
    return 0;
}
