#include <string.h>

void copy_header(const char *src, size_t n)
{
	char *dst;
~>	memcpy(dst,
	       src, n);
}

int read_flag(void)
{
	int *flag;
~>	*flag = 1;
	return 0;
}
