#include <stdlib.h>

struct rec {
    char name[32];
    char *heap;
};

void release(char buf[], struct rec *r)
{
    free(buf);
    free(r->heap);
}

void self_delete(void)
{
    sdsfree(&tmp);
}
