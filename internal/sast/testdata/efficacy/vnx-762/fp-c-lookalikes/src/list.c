#include <stdlib.h>

void rebuild(struct list *l)
{
    char *new_buf = malloc(l->cap * 2);
    char *renew = calloc(1, 8);
    memcpy(new_buf, l->buf, l->cap);
    free(l->buf);
    free(new_buf);
    free(renew);
    puts("new memory released with free()");
}
