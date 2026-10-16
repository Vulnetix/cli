#include <ctype.h>
#include <stddef.h>

int all_hex(const unsigned char *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (!isxdigit(buf[i]))
			return 0;
	}
	return 1;
}
