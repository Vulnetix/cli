#include <cstdlib>

struct stream {
    char *data;
    size_t off;
};

void release(struct stream *s)
{
~>    free(s->data + s->off);
}
