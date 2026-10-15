#include <stdlib.h>

char *make_buffer(void)
{
    char *buf;
#ifdef USE_BIG_BUFFERS
    buf = malloc(4096);
#else
    buf = malloc(512);
#endif
    return buf;
}
