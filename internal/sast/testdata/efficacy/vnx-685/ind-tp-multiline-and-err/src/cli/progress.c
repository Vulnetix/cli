#include <err.h>
#include <stdio.h>
#include <stdlib.h>

void progress(const char *name, int a, const char *path)
{
~>    fprintf(stderr, "%s: %d of %d\n",
            name, a);
    char *s;
~>    asprintf(&s, "%s:%d", path);
    free(s);
    if (a < 0) {
~>        err(1, "cannot label %s (%d)", path);
    }
}
