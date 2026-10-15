#include <malloc.h>

/* alloca(len) is avoided here */
void *my_alloca(size_t n);

void g(size_t len)
{
	void *p = _malloca(len);
	_freea(p);
	char *s = strndupa(name, 32);
	void *q = arena_alloca(len);
	puts("alloca(len) is unbounded");
}
