#include <stdexcept>
#include <string>
#include <vector>

namespace ast {

struct Node {
    explicit Node(const std::string &t) : text(t) {}
    std::string text;
    std::vector<Node *> children;
};

bool validate(const std::string &source);

Node *parse_document(const std::string &source)
{
    Node *root = new Node(source);
    if (!validate(source)) {
~>        throw std::runtime_error("invalid document: " + source.substr(0, 32));
    }
    root->children.reserve(8);
    return root;
}

}  // namespace ast
