#include <err.h>
#include <stdio.h>
#include <stdlib.h>

char *label(const char *path, int id)
{
    char *s;
~>    asprintf(&s, "%s:%d", path);
    if (s == NULL)
~>        err(1, "cannot label %s (%d)", path);
    (void)id;
    return s;
}
