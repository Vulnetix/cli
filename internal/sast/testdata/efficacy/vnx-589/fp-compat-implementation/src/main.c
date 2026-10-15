#include "compat.h"

void set_name(char *buf, size_t n, const char *name)
{
    strlcpy(buf, name, n);
}
