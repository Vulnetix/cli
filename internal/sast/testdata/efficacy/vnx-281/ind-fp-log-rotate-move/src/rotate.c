#include <stdio.h>
#include <limits.h>

/* Shift app.log.N to app.log.N+1, then app.log to app.log.1. */
int rotate_logs(const char *base, int keep)
{
    char from[PATH_MAX], to[PATH_MAX];

    for (int i = keep - 1; i >= 1; i--) {
        snprintf(from, sizeof from, "%s.%d", base, i);
        snprintf(to, sizeof to, "%s.%d", base, i + 1);
        rename(from, to);
    }
    snprintf(to, sizeof to, "%s.1", base);
    return rename(base, to);
}
