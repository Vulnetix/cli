#include <string.h>

struct node {
	char *data;
	size_t size;
};

/* pos is always < node->size: callers walk the rope with node_seek(). */
void node_tail(const struct node *node, size_t pos, char *out)
{
	memcpy(out, node->data + pos, node->size - pos);
}
