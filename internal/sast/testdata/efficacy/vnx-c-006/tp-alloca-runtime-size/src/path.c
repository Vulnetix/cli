#include <alloca.h>
#include <string.h>

int open_under(const char *root, const char *name)
{
~>    char *path = alloca(strlen(root) + strlen(name) + 2);

    strcpy(path, root);
    strcat(path, "/");
    strcat(path, name);
    return open_path(path);
}

void fill(size_t count)
{
~>    int *slots = (int *)alloca(count * sizeof(int));
    memset(slots, 0, count * sizeof(int));
}
