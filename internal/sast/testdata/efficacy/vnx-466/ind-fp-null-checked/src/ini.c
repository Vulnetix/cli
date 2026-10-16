#include <string.h>

const char *ini_value(const char *entry)
{
    const char *eq = strchr(entry, '=');
    if (eq == NULL)
        return NULL;
    return eq + 1;
}

const char *basename_of(const char *s)
{
    const char *p = strrchr(s, '/');
    if (!p) return s;
    return p + 1;
}
