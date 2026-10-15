#include <stdlib.h>
#include <string.h>

struct table { char **keys; size_t n; };

struct table *table_new(size_t n)
{
    struct table *t = (struct table *)malloc(sizeof(*t));
~>    t->n = n;
    t->keys = calloc(n, sizeof(char *));
    if (t->keys == NULL)
        return NULL;
    return t;
}

char *dup_name(const char *src)
{
    char *copy = strndup(src, 64);
    /* normalise */
~>    copy[0] = (char)toupper(copy[0]);
    return copy;
}
