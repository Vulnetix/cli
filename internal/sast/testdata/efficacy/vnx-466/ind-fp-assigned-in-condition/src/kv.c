#include <string.h>

const char *kv_value(const char *s)
{
    const char *p;
    if ((p = strchr(s, ':')) != NULL)
        return p + 1;
    return s;
}
