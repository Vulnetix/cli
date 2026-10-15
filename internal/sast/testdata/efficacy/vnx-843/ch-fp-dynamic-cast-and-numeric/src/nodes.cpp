#include <cstdint>

class Node {
public:
    virtual ~Node() = default;
};

class Leaf : public Node {
public:
    int value = 0;
};

int leaf_value(Node *n, double scale)
{
    if (auto *leaf = dynamic_cast<Leaf *>(n)) {
        return leaf->value + static_cast<int>(scale);
    }
    uint8_t b = static_cast<uint8_t>(scale);
    Node *base = static_cast<Node *>(new Leaf());
    delete base;
    return (int)b;
}
