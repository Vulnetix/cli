#include <stdlib.h>
#include <string.h>

#define DEFAULT_NAME "anonymous"

struct cfg { char name[32]; char mode[8]; };

void defaults(struct cfg *c, int ro)
{
    strcpy(c->name, "default");
    strcpy(c->name, DEFAULT_NAME);
    strcpy(c->mode, ro ? "ro" : "rw");
}

char *dup_str(const char *s)
{
    char *p = malloc(strlen(s) + 1);
    if (p == NULL)
        return NULL;
    strcpy(p, s);
    return p;
}
