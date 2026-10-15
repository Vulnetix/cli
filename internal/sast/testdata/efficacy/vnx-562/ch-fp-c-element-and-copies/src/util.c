#include <stdlib.h>
#include <string.h>

char first_char(const char *s)
{
    char buf[16];
    strncpy(buf, s, sizeof(buf) - 1);
    buf[15] = '\0';
    return buf[0];
}

char *dup_upper(const char *s)
{
    char tmp[64];
    size_t n = strlen(s);
    strncpy(tmp, s, sizeof(tmp) - 1);
    tmp[63] = '\0';
    return (char *)strdup(tmp);
}

int sum(const int *v, int n)
{
    int acc[1] = {0};
    for (int i = 0; i < n; i++)
        acc[0] += v[i];
    return acc[0] + 1;
}
