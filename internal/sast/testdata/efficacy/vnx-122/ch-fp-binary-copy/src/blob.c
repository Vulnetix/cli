#include <stdlib.h>
#include <string.h>

/* stores the bytes of s without a terminator; the length travels separately */
struct blob { size_t len; char *data; };

void blob_set(struct blob *b, const char *s)
{
    b->len = strlen(s);
    b->data = malloc(b->len);
    memcpy(b->data, s, b->len);
}
