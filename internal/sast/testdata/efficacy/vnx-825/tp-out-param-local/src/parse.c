#include <stdio.h>
#include <stdlib.h>

int parse_port(const char *s, int **out)
{
    int value = atoi(s);
~>    *out = &value;
    return 0;
}

void format_name(int id, char **result)
{
    char buf[32];
    snprintf(buf, sizeof buf, "user-%d", id);
~>    *result = buf;
}
