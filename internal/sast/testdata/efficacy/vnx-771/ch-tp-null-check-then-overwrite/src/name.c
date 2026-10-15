#include <stdlib.h>
#include <string.h>

int set_names(const char *first, const char *second)
{
~>    char *name = strdup(first);
    if (!name)
        return -1;
    puts(name);
    name = strdup(second);
    if (name == NULL)
        return -1;
    puts(name);
    free(name);
    return 0;
}
