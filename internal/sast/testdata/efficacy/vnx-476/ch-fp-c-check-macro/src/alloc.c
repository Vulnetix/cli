#include <stdlib.h>
#include <string.h>
#include "check.h"

char *make_name(const char *base)
{
    char *name = malloc(strlen(base) + 8);
    RETURN_IF_NULL(name);
    strcpy(name, base);
    return name;
}

char *make_tag(const char *base)
{
    char *tag = strdup(base);
    CHECK_ALLOC(tag);
    tag[0] = '#';
    return tag;
}
