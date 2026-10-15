#include <stdlib.h>

enum owner { OWNER_HEAP, OWNER_POOL, OWNER_STATIC };

void blob_release(struct blob *b, struct pool *pool)
{
	if (b->owner == OWNER_HEAP) free(b->data);
	if (b->owner == OWNER_POOL) pool_return(pool, b->data);
	if (b->owner == OWNER_STATIC) return;
	b->data = NULL;
}

void name_release(char *name, int heap, int copied)
{
	if (heap)
		free(name);
	else if (copied)
		free(name);
}
