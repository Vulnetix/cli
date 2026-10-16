#include <stdio.h>

void join(char *buf, const char *file)
{
~>    sprintf(buf, "%s/%s", buf, file);
}

void prefix(char *msg, size_t n, const char *err)
{
~>    snprintf(msg, n, "%s: %s", msg, err);
}
