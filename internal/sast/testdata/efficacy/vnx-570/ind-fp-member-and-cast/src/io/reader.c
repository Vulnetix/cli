#include <stddef.h>

struct reader {
    long pos;
    size_t cap;
};

int reader_ok(const struct reader *r)
{
    if (r->pos < 0) {
        return 0;
    }
    if ((long)r->cap < 0) {
        return 0;
    }
    return 1;
}
