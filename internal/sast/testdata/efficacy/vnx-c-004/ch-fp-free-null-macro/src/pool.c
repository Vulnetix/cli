#include <stdlib.h>

#define SAFE_FREE(p) do { free(p); (p) = NULL; } while (0)

void pool_drop(struct pool *pl)
{
	free(pl->items);
	pl->items = NULL;
	pl->count = 0;
	SAFE_FREE(pl->name);
	free(pl);
}

void buf_regrow(struct buf *b, size_t n)
{
	free(b->data);
	b->data = malloc(n);
	b->data[0] = 0;
}
