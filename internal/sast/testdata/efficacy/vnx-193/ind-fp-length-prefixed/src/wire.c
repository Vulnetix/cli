#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct lp_string {
	uint32_t len;
	char *bytes;
};

/* Wire strings are length-prefixed and never NUL-terminated. */
int lp_from_cstr(struct lp_string *dst, const char *src)
{
	dst->len = (uint32_t)strlen(src);
	dst->bytes = malloc(strlen(src));
	if (dst->bytes == NULL)
		return -1;
	memcpy(dst->bytes, src, dst->len);
	return 0;
}
