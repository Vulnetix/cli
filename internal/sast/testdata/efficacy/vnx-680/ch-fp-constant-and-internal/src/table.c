#include <stdlib.h>

struct table { int len; int *slots; };

void table_init(struct table *t, int len)
{
    int *tmp = malloc(16 * sizeof(int));
    t->slots = malloc(t->len * sizeof(int));
    char *msg = "malloc(atoi(s) * 4)";
    free(tmp);
    (void)msg;
}
