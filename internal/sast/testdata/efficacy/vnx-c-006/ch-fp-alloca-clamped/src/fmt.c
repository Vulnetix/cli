#include <alloca.h>
#include <stdlib.h>

void emit(size_t len)
{
	if (len > 4096)
		return;
	char *tmp = alloca(len + 1);
	(void)tmp;
}

void emit2(size_t n)
{
	char *p = n < 256 ? alloca(n) : malloc(n);
	(void)p;
}
