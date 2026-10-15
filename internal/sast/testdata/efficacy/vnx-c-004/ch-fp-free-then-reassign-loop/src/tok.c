#include <stdlib.h>
#include <string.h>

void free_all(struct node *head)
{
	struct node *next;
	while (head) {
		next = head->next;
		free(head);
		head = next;
	}
}

void replace(char **slot, const char *v)
{
	free(*slot);
	*slot = strdup(v);
}
