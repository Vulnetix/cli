#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int parse_line(const char *in)
{
    char *line = strdup(in);
    if (line == NULL)
        return -1;
    while (isspace((unsigned char)*line))
        line++;
    int n = atoi(line);
~>    free(line);
    return n;
}

char *copy_upper(const char *src, size_t n)
{
    char *out = malloc(n + 1);
    for (size_t i = 0; i < n; i++)
        *out++ = toupper((unsigned char)src[i]);
    *out = '\0';
~>    free(out);
    return NULL;
}

void skip_magic(size_t n)
{
    unsigned char *buf = (unsigned char *)calloc(n, 1);
    buf += 4;
~>    free(buf);
}
