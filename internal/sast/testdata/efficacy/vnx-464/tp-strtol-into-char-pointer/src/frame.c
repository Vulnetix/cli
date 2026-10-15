#include <stdlib.h>

char *make_tag(const char *arg)
{
    char *tag = malloc(4);
    tag[0] = 'T';
~>    tag[1] = (char)strtol(arg, NULL, 10);
    tag[2] = '\0';
    return tag;
}
