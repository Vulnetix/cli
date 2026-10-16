#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *version_string(void)
{
    static char buf[32];
    snprintf(buf, sizeof buf, "v%d.%d", 3, 12);
    return buf;
}

char *dup_name(const char *first, const char *last)
{
    size_t n = strlen(first) + strlen(last) + 2;
    char *out = malloc(n);
    if (out == NULL) {
        return NULL;
    }
    snprintf(out, n, "%s %s", first, last);
    return out;
}

static __thread char tls_err[128];

const char *last_error(void)
{
    return tls_err;
}
