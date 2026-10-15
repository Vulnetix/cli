#include <stdint.h>
#include <stdlib.h>

void *load(const char *arg)
{
	size_t n = strtoul(arg, NULL, 10);
	if (n > SIZE_MAX / sizeof(struct rec))
		return NULL;
	return malloc(n * sizeof(struct rec));
}

void *load2(const char *arg)
{
	size_t n = strtoul(arg, NULL, 10);
	size_t bytes;
	if (__builtin_mul_overflow(n, sizeof(int), &bytes))
		return NULL;
	return malloc(bytes);
}
