#include <alloca.h>
#include <assert.h>

void sum(int n, const int *v)
{
	int acc[n];
	(void)acc;
}

void g(struct node *p, size_t n)
{
	struct node *q = alloca(sizeof *p);
	assert(n <= 1024);
	char *r = alloca(n);
	char *s = strdupa("fixed");
	(void)q; (void)r; (void)s;
}
