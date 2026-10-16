#include <stdio.h>
#include <stdlib.h>

#define LABEL_LEN 64

char *make_label(const char *host, int port)
{
    char *buf = malloc(LABEL_LEN);
    if (!buf)
        return NULL;
    snprintf(buf, LABEL_LEN, "%s:%d", host, port);
    return buf;
}
