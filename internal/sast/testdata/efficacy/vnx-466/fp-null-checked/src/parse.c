#include <string.h>
#include <assert.h>

const char *value_or_empty(const char *entry)
{
    const char *p = strchr(entry, '=');
    if (p == NULL)
        return "";
    return p + 1;
}

const char *after_colon(const char *s)
{
    const char *p = strrchr(s, ':');
    if (!p) return s;
    return p + 1;
}

const char *ternary(const char *s)
{
    const char *p = strchr(s, '/');
    return p ? p + 1 : s;
}

char *assignment_in_condition(char *s)
{
    char *q;
    if ((q = strstr(s, "--")) != NULL) {
        return q + 2;
    }
    return s;
}

char *asserted(char *s)
{
    char *p = strchr(s, '\r');
    assert(p);
    return p + 2;
}

char *reassigned(char *s)
{
    char *p = strchr(s, '#');
    p = s;
    return p + 1;
}

const char *guarded(const char *s)
{
    const char *p = memchr(s, ';', 32);
    if (p != NULL && p[1] != '\0')
        return p + 1;
    return NULL;
}
