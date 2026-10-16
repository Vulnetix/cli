struct node { int value; struct node *next; };

void set_value(int v)
{
    struct node *n;
~>    n->value = v;
}
