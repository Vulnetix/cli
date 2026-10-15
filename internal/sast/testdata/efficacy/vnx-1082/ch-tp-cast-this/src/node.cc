#include "node.h"

void Node::destroySelf() {
    onDestroy();
~>    delete static_cast<DerivedNode*>(this);
}

void Node::finalize() {
~>    std::destroy_at(this);
}
