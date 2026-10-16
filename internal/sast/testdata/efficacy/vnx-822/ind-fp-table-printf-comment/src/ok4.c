#include <stdio.h>
#include <stdlib.h>
struct ent { int v; };
static struct ent table[16];
int get(const char *s)
{
    unsigned idx = (unsigned)strtoul(s, NULL, 10);
    if (idx >= 16) return -1;
    struct ent *e = &table[idx];
    printf("%p\n", (void *)e);
    /* char *p = (char *)strtoul(s, NULL, 16); */
    return e->v;
}
