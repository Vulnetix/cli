#include <alloca.h>
#include <stdlib.h>
#include <string.h>

#define SCRATCH 256

struct hdr { int a; int b; };

void fmt_header(size_t n)
{
	struct hdr *h = alloca(sizeof(struct hdr));
	char *tmp = alloca(SCRATCH * 2);
	char *s = n <= 512 ? alloca(n) : malloc(n);
	char line[SCRATCH];
	(void)h; (void)tmp; (void)s; (void)line;
}

void *my_alloca_pool(size_t n);
void use_pool(size_t n)
{
	void *p = my_alloca_pool(n);
	(void)p;
}
