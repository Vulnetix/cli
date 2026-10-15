#include <stdlib.h>
#include <string.h>

int fill(size_t n)
{
    char *buf = malloc(n + 1);
    char *p = buf;
    if (buf == NULL)
        return -1;
    for (size_t i = 0; i < n; i++)
        *p++ = 'x';
    *p = '\0';
    free(buf);
    return 0;
}

char *grow(char *data, size_t len)
{
    char *tmp = realloc(data, len + 16);
    if (tmp == NULL) {
        free(data);
        return NULL;
    }
    data = tmp;
    data[len] = '\0';
    return data;
}

void counter(void)
{
    int *count = malloc(sizeof *count);
    *count = 0;
    (*count)++;
    *count += 2;
    free(count);
}
