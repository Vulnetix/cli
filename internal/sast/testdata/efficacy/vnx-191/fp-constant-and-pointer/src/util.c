#include <string.h>

void fill(char *dst, const char *start, const char *end)
{
	char buf[64];
	memset(buf, 0, sizeof(buf) - 1);
	memcpy(dst, start, end - start);
	strncpy(dst, buf, sizeof(buf) - 1);
}
