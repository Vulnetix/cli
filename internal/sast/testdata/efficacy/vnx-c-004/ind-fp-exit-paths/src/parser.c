#include <stdio.h>
#include <stdlib.h>

struct doc { char *text; int lines; };

int parse(const char *path, struct doc **out)
{
    struct doc *d = malloc(sizeof(*d));
    if (d == NULL)
        return -1;
    d->text = NULL;
    if (load_text(path, &d->text) != 0) {
        free(d);
        goto fail;
    }
    if (d->lines == 0) {
        free(d->text);
        free(d);
        return -2;
    }
    *out = d;
    return 0;
fail:
    fprintf(stderr, "cannot parse %s\n", path);
    return -1;
}
