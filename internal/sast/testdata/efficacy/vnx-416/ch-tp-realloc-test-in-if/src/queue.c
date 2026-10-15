#include <stdlib.h>

int queue_push(struct queue *qu, int v)
{
	int *grown;
	if ((grown = realloc(qu->slots, qu->cap * 2 * sizeof(int))) == NULL)
		return -1;
	qu->cap *= 2;
~>	qu->slots[qu->len++] = v;
	qu->slots = grown;
	return 0;
}
