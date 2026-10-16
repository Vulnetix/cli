#include <stdlib.h>

static char cache[256];

void flush(void)
{
~>    free(cache);
}
