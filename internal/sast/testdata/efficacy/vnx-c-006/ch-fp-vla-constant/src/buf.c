#include <alloca.h>
#define BUFSZ 128

void f(void)
{
	char a[BUFSZ];
	char b[sizeof(long) * 4];
	char *c = alloca(64);
	char *d = alloca(sizeof(struct hdr) + 16);
	(void)a; (void)b; (void)c; (void)d;
}
