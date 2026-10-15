#include <stdlib.h>
#include <stdio.h>

struct item { int field; };

int parse_port(const char *s, int **out)
{
    static int value;
    value = atoi(s);
    *out = &value;
    return 0;
}

void format_name(int id, char **result, struct item *it)
{
    static char buf[32];
    snprintf(buf, sizeof buf, "user-%d", id);
    *result = buf;
    char *heap = malloc(16);
    *result = heap;
}

void field_of(struct item *it, int **out)
{
    *out = &it->field;
}
