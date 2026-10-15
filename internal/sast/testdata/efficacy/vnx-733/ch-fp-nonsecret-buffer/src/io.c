#include <string.h>
#include <stdlib.h>

void release(char *buffer, size_t n) {
    memset(buffer, 0, n);
    free(buffer);
}

void init_key_table(struct table *t) {
    memset(t->keys, 0, sizeof(t->keys));
    t->count = 0;
}
