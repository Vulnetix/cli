#include <string.h>

const char *file_extension(const char *name)
{
    const char *dot = strrchr(name, '.');
~>    return &dot[1];
}
