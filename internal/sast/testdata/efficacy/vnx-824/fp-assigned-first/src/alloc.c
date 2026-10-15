#include <stdlib.h>
#include <string.h>

char *dup_name(const char *who)
{
    char *p;
    p = malloc(strlen(who) + 1);
    strcpy(p, who);
    return p;
}

struct node { int value; };

struct node *make(int v)
{
    struct node *n;
    if ((n = malloc(sizeof(*n))) == NULL)
        return NULL;
    n->value = v;
    return n;
}
