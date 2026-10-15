#include <string.h>

int count_slash_star(const char *s)
{
    const char *pat = "/*";
    int hits = 0;
scan:
    s = strstr(s, pat);
    if (s != NULL) {
        hits++;
        s += 2;
~>        goto scan;
    }
    return hits;
}
