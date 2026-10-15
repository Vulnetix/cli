#include <vector>
#include "node.hpp"

int countLeaves(const std::vector<Node> &nodes)
{
    int leaves;
    for (const auto &n : nodes) {
        if (n.children.empty()) {
~>            leaves++;
        }
    }
    return leaves;
}
