#include <string.h>

void set_name(const char *src)
{
    char name[32];
    strncpy(name, src, sizeof(name));
~>    name[sizeof(name)] = '\0';
}
