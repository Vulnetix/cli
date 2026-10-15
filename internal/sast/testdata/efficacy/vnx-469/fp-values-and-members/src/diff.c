#include <stddef.h>

struct span { char *start; char *end; };

int compare(void)
{
    int expected[4] = {1, 2, 3, 4};
    int actual[4] = {1, 2, 3, 5};
    int delta = actual[3] - expected[3];
    int first = *actual - *expected;
    size_t sz = sizeof(actual) - sizeof(expected);
    return delta + first + (int)sz;
}

size_t span_len(struct span *s, struct span other)
{
    int total = 10;
    int consumed = 3;
    int remaining = total - consumed;
    return (size_t)(s->end - s->start) + (size_t)(other.end - other.start) + (size_t)remaining;
}
