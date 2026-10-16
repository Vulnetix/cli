#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *short_name(const char *full)
{
    char *s = malloc(48);
    if (!s)
        return NULL;
    sprintf(s, "user-%.40s", full);
    return s;
}

char *copy_name(const char *full)
{
    return strdup(full);
}
