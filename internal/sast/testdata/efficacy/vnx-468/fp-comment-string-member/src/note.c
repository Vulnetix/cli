#include <stdio.h>

/* wrong: int *p; p + i * sizeof(int) */
// q += sizeof(struct record);
void note(struct conn *c, int *p)
{
    puts("p + i * sizeof(int) skips too far");
    send(c->buf + c->used * sizeof(int));
    p = p + 4;
}
