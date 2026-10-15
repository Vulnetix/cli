struct Node { Node *next; int state; };

int drain(Node *n)
{
    int count = 0;
~>    while (n->state = 1) {
        count++;
        n = n->next;
    }
    return count;
}
