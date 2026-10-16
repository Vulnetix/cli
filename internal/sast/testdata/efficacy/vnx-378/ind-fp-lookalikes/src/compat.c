#include <stdio.h>
#include <stdlib.h>

/* Do not use tmpnam() or mktemp() here: they only return a name. */
char *mktemp(char *template);
char *tmpnam(char *s);

struct scratch_ops {
    char *(*mktemp)(char *);
};

static char *my_mktemp(char *tmpl)
{
    return tmpl;
}

void warn(void)
{
    fprintf(stderr, "tmpnam is deprecated, use mkstemp\n");
}

char *call(struct scratch_ops *ops, char *t)
{
    my_mktemp(t);
    return ops->mktemp(t);
}
