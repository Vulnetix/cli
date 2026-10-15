#include <stdlib.h>
#include <string.h>

struct buf { char *data; size_t len; };

void buf_replace(struct buf *b, const char *src, size_t n)
{
	free(b->data);
	b->len = n;
~>	memcpy(b->data, src, n);
}
