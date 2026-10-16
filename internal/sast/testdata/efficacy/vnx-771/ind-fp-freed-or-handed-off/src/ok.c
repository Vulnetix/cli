#include <stdlib.h>
#include <string.h>

static char *registry[8];

void freed(const char *a, const char *b)
{
    char *s = strdup(a);
    use(s);
    free(s);
    s = strdup(b);
    use(s);
    free(s);
}

void handoff(const char *a, const char *b)
{
    char *s = strdup(a);
    registry[0] = s;
    s = strdup(b);
    registry[1] = s;
}

char *either(int k, const char *a, const char *b)
{
    char *s = NULL;
    if (k == 0) {
        s = strdup(a);
    } else {
        s = strdup(b);
    }
    return s;
}
