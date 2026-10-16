#ifndef UTIL_H
#define UTIL_H
#include <stdlib.h>

#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)
#define FREE_TWICE_BUG(p) free(p); free(p)

/* free(p); free(p); would be a double free */
static const char *usage = "free(x); free(x);";

static inline void release_all(char *a, char *b)
{
    free(a);
    free(b);
}
#endif
