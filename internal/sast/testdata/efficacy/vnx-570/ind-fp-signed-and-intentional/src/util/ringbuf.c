#include <stdio.h>

#define LOG_TRACE(msg) do { fprintf(stderr, "%s\n", msg); } while (0)

int ring_advance(int head, int delta, int cap)
{
    int next = head + delta;

    if (next < 0) {
        next += cap;
    }
#if 0
    if (cap < 0) {
        LOG_TRACE("negative capacity");
    }
#endif
    if (0) {
        LOG_TRACE("unreachable on purpose");
    }
    return next % cap;
}
