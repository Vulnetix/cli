#include <ctype.h>
#include <stdlib.h>
#include <string.h>

int parse_value(const char *raw, long *out)
{
    char *s = strdup(raw);
    if (s == NULL)
        return -1;
    while (isspace((unsigned char)*s))
        s++;
    *out = strtol(s, NULL, 10);
~>    free(s);
    return 0;
}

void drop_prefix(char *line)
{
~>    free(line + 1);
}
