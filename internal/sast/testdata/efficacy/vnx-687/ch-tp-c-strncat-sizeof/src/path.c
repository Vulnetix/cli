#include <string.h>

void join(const char *name)
{
    char path[128] = "/var/lib/app/";
~>    strncat(path, name, sizeof(path));
}
