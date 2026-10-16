#include <string.h>

const char *file_extension(const char *path)
{
    const char *ext = strrchr(path, '.');
~>    return ext + 1;
}
