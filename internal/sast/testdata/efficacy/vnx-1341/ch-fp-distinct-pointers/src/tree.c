#include <stdlib.h>

void node_free(struct node *n)
{
    free(n->left);
    free(n->right);
    free(n->name);
    free(n->name_buf);
    free(items[0]);
    free(items[1]);
    free(n);
}
