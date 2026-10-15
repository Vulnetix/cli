#include <stdlib.h>
#include <string.h>

long parse(const char *s, int *ok)
{
    char *end;
    long v = strtol(s, &end, 10);
    *ok = (*end == '\0');
    return v;
}

char *dup_first(const char *csv)
{
    char *copy;
    char *tok;
    copy = strdup(csv);
    tok = strtok(copy, ",");
    return tok ? strdup(tok) : NULL;
}

void walk(char **items)
{
    const char *p;
    for (p = items[0]; *p; p++)
        ;
}
