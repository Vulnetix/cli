#include <stdint.h>

struct frame { uint8_t kind; };

void decode(void *data, char *raw)
{
    char buf[64];
    struct frame *f = (struct frame *)buf;
    struct frame *g = (struct frame *)data;
    struct frame *h = (struct frame *)(void *)raw;
    struct frame *k = (struct frame *)&buf[0];
    f->kind = g->kind + h->kind + k->kind;
}
