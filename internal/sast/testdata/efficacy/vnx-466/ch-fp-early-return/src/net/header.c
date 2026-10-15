#include <string.h>

char *header_value(char *line)
{
    char *colon = strchr(line, ':');
    if (!colon) {
        return NULL;
    }
    while (*++colon == ' ')
        ;
    return colon;
}

char *after_prefix(char *s, size_t n)
{
    char *p = s;
    return p + n;
}
