#include "parser.h"

bool Parser::parse(const std::string &text)
{
    Node *root = new Node(text);
    if (!tokenize(text)) {
~>        return false;
    }
    tree_.reset(root);
    return true;
}
