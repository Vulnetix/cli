#include <vector>

struct Node {
    int value;
    Node *next;
};

void push(int v)
{
    Node *n;
~>    n->value = v;
}

void collect()
{
    std::vector<int> *out;
~>    out->push_back(1);
}

void clear()
{
    Node *victim;
~>    delete victim;
}
