#include <stdlib.h>
#include <string.h>

struct conn { char *label; };
static struct conn *active;

int a(char **out)
{
    char *p = malloc(16);
    *out = p;
    return 0;
}

int b(char **out)
{
    static char buf[16];
    *out = buf;
    return 0;
}

void c(struct conn *cn, struct conn *global)
{
    struct conn local;
    active = &local;
    active = NULL;
    (void)cn; (void)global;
}
