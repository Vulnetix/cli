#include <stdlib.h>

void *pool_grow(void *pool)
{
	long extra = strtol(getenv("POOL_EXTRA"), NULL, 10);
	size_t bytes = extra * 4096;
~>	return realloc(pool, bytes);
}
