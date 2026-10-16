#include <stddef.h>
#include <string.h>

void stage(const char *in)
{
    char src[64];
    char dst[128];
    strncpy(src, in, sizeof(src) - 1);
~>    ptrdiff_t room = dst - src;
    (void)room;
}
