#include <stdlib.h>

struct rec *load_records(const char *arg)
{
	unsigned long n = strtoul(arg, NULL, 10);
~>	struct rec *r = malloc(n * sizeof(struct rec));
	return r;
}
