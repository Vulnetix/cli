#include <alloca.h>
#include <string.h>

void emit(const char *name, size_t len)
{
~>	char *tmp = alloca(len + 1);
	memcpy(tmp, name, len);
	tmp[len] = 0;
}

void join(const char *a, const char *b)
{
~>	char *p = (char *)alloca(strlen(a) +
	                          strlen(b) + 2);
	(void)p;
}
