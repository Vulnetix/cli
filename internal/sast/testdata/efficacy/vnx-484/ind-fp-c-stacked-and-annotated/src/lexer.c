#include "lexer.h"

int classify(int ch, struct lex *lx)
{
    switch (ch) {
    case ' ':
    case '\t':
    case '\r':
        return TK_SPACE;
    case '\n':
        lx->line++;
        /* fall through */
    case ';':
        lx->stmt_end = 1;
        return TK_END;
    case '#':
        lx->in_comment = 1;
        __attribute__((fallthrough));
    case '/':
        return TK_SLASH;
    case 0:
        exit(2);
    case 4:
        abort();
    default:
        lx->other++;
    }
    return TK_OTHER;
}
