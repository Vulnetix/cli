#include <stdlib.h>
#include <string.h>

size_t token_length(const char *line)
{
    const char *end = strchr(line, ' ');
    if (!end)
        return strlen(line);
    return end - line;
}

size_t used(size_t cap)
{
    char *buf = malloc(cap);
    char *cursor = buf + 10;
    size_t n = cursor - buf;
    char *grown = realloc(buf, cap * 2);
    free(grown);
    return n;
}

size_t offset_in(void)
{
    char table[128];
    char *hit = memchr(table, 0, sizeof table);
    return hit ? (size_t)(hit - table) : 0;
}
