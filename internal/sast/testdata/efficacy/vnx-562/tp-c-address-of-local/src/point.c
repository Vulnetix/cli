#include <stdlib.h>

struct point { int x; int y; };

struct point *origin(void)
{
    struct point p = { 0, 0 };
~>    return &p;
}

int *counter(int start) {
    int value = start + 1;
~>    return &value;
}

int *param_addr(int v)
{
~>    return &v;
}

char **holder(void) {
    char *name = malloc(8);
~>    return &name;
}
