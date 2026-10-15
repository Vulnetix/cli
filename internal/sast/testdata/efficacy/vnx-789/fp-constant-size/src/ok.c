#include <stdlib.h>
#include <string.h>

char *dup_name(const char *s)
{
    size_t len = strlen(s);
    char *p = malloc(len + 1);
    char *q = malloc(64);
    int port = atoi(s);
    char *r = malloc(sizeof(int) * 4);
    (void)port;
    return p ? p : q ? q : r;
}
