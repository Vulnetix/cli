class Node {
public:
    Node *next;
    int value;
};

int walk()
{
    int seed = 42;
~>    Node *n = reinterpret_cast<Node *>(&seed);
    return n->value;
}
