#include <ctype.h>

const unsigned char *skip_ws(const unsigned char *u)
{
    while (isspace(*u))
        u++;
    return u;
}
