#include <stdlib.h>

void list_remove(struct list *l, struct node *n)
{
	free(n);
~>	l->count -= n->weight;
}

void drop_first(struct list *l)
{
	struct node *head = l->head;
	free(head);
~>	l->head = head->next;
}
