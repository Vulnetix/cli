#include <stdlib.h>
#include <string.h>

char *dup_or_die(const char *s)
{
    char *copy = strdup(s);
    if (copy == NULL)
        abort();
    return copy;
}

int open_cfg(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    fclose(fp);
    return 0;
}
