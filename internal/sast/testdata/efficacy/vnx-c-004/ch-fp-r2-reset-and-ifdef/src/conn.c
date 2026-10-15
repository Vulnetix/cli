#include <stdlib.h>
#include <string.h>

struct conn { char *rbuf; size_t rlen; struct conn *next; };

void conn_reset(struct conn *c, size_t n)
{
	free(c->rbuf);
	c->rbuf = malloc(n);
	memset(c->rbuf, 0, n);
	c->rlen = 0;
}

void conn_free_all(struct conn *head)
{
	struct conn *next;
	while (head) {
		next = head->next;
		free(head);
		head = next;
	}
}

char *swap_name(char *old, const char *name)
{
	free(old);
	old = strdup(name);
	return old;
}
