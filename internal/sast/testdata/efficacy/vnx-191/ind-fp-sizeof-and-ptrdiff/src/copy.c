#include <string.h>

void copy_name(char *dst_in, const char *src, const char *end)
{
	char name[64];
	char *dst = dst_in;

	strncpy(name, src, sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';
	/* pointer difference: end is always at or after src */
	memcpy(dst, src, end - src);
}
