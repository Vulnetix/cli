#include <stdio.h>

void flush_log(const char *path, const char *buf, size_t n)
{
    FILE *fp = fopen(path, "a");
    serverAssert(fp);
    fwrite(buf, n, 1, fp);
    fclose(fp);
}
