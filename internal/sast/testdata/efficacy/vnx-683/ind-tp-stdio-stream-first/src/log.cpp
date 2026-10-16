#include <cstdio>

void emit(FILE *fp, const char *msg, const char *buf, size_t n)
{
~>    fputs(stderr, msg);
~>    fwrite(fp, buf, 1, n);
    std::fflush(fp);
}
