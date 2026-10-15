#include <string.h>

struct node { size_t size; unsigned char data[]; };

/* Remove pos from the node: the node's own size is always > pos here. */
void node_remove(struct node *n, size_t pos)
{
	memmove(n->data + pos, n->data + pos + 1, n->size - pos - 1);
	n->size--;
}

void list_concat(unsigned char *target, const unsigned char *source)
{
	size_t source_bytes = list_bytes(source);
	size_t target_bytes = list_bytes(target);
	memcpy(target + target_bytes - 1, source, source_bytes - 1);
}
