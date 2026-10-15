#include <stdlib.h>

char *canon(const char *p)
{
    /* realpath(p, small) with char small[16] would truncate */
    char *r = realpath(p, NULL);
    return r;
}
