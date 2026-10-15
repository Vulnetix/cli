#include <ctype.h>

const char *skip_ws(const char *p)
{
~>    while (isspace(*p))
        p++;
    return p;
}
