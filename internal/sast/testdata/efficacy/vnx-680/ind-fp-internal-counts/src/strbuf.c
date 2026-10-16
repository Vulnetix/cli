#include <stdlib.h>
#include <string.h>

#define MAX_ITEMS 128

struct strbuf {
    char *data;
    size_t len;
    size_t cap;
};

int strbuf_grow(struct strbuf *sb)
{
    size_t cap = sb->cap ? sb->cap : 16;
    char *p = realloc(sb->data, cap * 2);
    if (!p) {
        return -1;
    }
    sb->data = p;
    sb->cap = cap * 2;
    return 0;
}

char *dup_wide(const char *s)
{
    char *copy = malloc(strlen(s) * sizeof(char) + 1);
    if (copy) {
        strcpy(copy, s);
    }
    return copy;
}

int *make_slots(void)
{
    return malloc(MAX_ITEMS * sizeof(int));
}
