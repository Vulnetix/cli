#include "parser.hpp"

namespace cfg {

int Parser::handleToken(const Token& tok) {
    switch (tok.kind) {
~>        case TokenKind::Include:
            if (depth_ > kMaxDepth) return -1;
        case TokenKind::Define:
            defines_.emplace(tok.name, tok.value);
            break;
        case TokenKind::End:
            return 0;
        default:
            throw ParseError("unexpected token");
    }
    return 1;
}

}  // namespace cfg
