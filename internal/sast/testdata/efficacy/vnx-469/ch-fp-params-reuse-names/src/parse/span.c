#include <stdlib.h>
#include <string.h>

char *make_buffers(size_t n, char **out_end)
{
    char *buf = malloc(n);
    char *end = malloc(n);
    *out_end = end;
    return buf;
}

size_t span_len(const char *buf, const char *end)
{
    return (size_t)(end - buf);
}

size_t used(char *start, size_t cap)
{
    char *buf = start;
    char *end = start + cap;
    return end - buf;
}
