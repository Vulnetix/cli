#include <assert.h>
#include <string.h>

void drop_slash(char *path)
{
    size_t n = strlen(path);
    assert(n > 0);
    if (path[n - 1] == '/')
        path[n - 1] = '\0';
}
