#include <stdio.h>

void append(char *buf, const char *file)
{
~>    sprintf(buf, "%s/%s", buf, file);
}

void counter(char *out, size_t size, int n)
{
~>    snprintf(out, size, "%s%d", out, n);
}
