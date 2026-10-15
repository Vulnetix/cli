#include <stdlib.h>
#include <string.h>

int blob_append(char *buf, size_t len, const char *src, size_t k)
{
	char *tmp;

	tmp = (char *)realloc(buf, len + k);
	if (tmp == NULL)
		return -1;
~>	memcpy(buf + len, src, k);
	return 0;
}

char *grow_and_return(char *old, size_t n)
{
	char *fresh = g_realloc(old, n);
	fresh[0] = 0;
~>	return old;
}
