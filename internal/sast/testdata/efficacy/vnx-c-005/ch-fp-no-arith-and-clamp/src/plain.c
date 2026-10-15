#include <stdlib.h>

char *plain(const char *s)
{
	size_t n = strtoul(s, NULL, 10);
	char *p = malloc(n);
	return p;
}

char *clamped(const char *s)
{
	int n = atoi(s);
	n = n > 100 ? 100 : n;
	return malloc(n * sizeof(int));
}
