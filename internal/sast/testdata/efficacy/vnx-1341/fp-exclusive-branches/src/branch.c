#include <stdlib.h>

int pick(char *p, int a)
{
    if (a) {
        free(p);
    } else {
        free(p);
    }
    return 0;
}

int by_kind(char *p, int kind)
{
    switch (kind) {
    case 1:
        free(p);
        break;
    case 2:
        free(p);
        break;
    }
    return 0;
}

int early(char *p, int bad)
{
    if (bad) {
        free(p);
        return -1;
    }
    free(p);
    return 0;
}

int inline_exit(char *p, int bad)
{
    if (bad) { free(p); return -1; }
    free(p);
    return 0;
}
