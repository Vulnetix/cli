#include "tree.hpp"

~>class Tree::Visitor {
public:
    virtual void visit(Node& n) = 0;
    ~Visitor();
};
