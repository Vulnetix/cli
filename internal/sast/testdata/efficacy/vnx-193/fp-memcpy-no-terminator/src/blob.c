#include <stdlib.h>
#include <string.h>

/* A length-prefixed blob: no terminator is ever written. */
struct blob { size_t len; char *data; };

int blob_from(struct blob *b, const char *s)
{
	b->len = strlen(s);
	b->data = malloc(strlen(s));
	if (!b->data)
		return -1;
	memcpy(b->data, s, b->len);
	return 0;
}
