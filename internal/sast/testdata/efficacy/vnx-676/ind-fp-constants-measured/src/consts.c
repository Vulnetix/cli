#include <string.h>
#include <stdlib.h>

#define DEFAULT_NAME "anonymous"

struct cfg { char name[16]; };

void init(struct cfg *c, const char *s) {
    strcpy(c->name, "default");
    strcpy(c->name, DEFAULT_NAME);
    char *p = malloc(strlen(s) + 1);
    strcpy(p, s);
    free(p);
}
