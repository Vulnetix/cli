#include <string.h>

void set_name(const char *src)
{
    char name[32];
    strncpy(name, src, sizeof(name));
~>    name[sizeof(name)] = '\0';
}

void set_tag(const char *src)
{
    char tag[8];
    memcpy(tag, src, sizeof tag);
~>    tag[ sizeof tag ] = 0;
}
