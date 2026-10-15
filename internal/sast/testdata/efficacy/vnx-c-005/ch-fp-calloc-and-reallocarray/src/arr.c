#include <stdlib.h>

void *arr(const char *arg, void *old)
{
	size_t n = strtoul(arg, NULL, 10);
	void *a = calloc(n, sizeof(int));
	void *b = reallocarray(old, n, sizeof(int));
	free(a);
	return b;
}
