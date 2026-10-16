#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} strbuf;

int strbuf_append(strbuf *sb, const char *s, size_t n)
{
    if (sb->len + n + 1 > sb->cap) {
        size_t newcap = sb->cap ? sb->cap * 2 : 64;
        while (newcap < sb->len + n + 1)
            newcap *= 2;
~>        sb->data = realloc(sb->data, newcap);
        if (sb->data == NULL)
            return -1;
        sb->cap = newcap;
    }
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
    return 0;
}
