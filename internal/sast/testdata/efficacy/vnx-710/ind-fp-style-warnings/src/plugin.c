#include <stddef.h>

#pragma warning(disable: 4100 4244)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

int plugin_init(void *host, int flags)
{
    unsigned n = 3;
    int k = -1;
    return n > k;
}
