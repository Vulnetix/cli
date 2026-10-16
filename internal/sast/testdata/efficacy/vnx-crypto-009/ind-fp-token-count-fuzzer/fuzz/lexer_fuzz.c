#include <stdlib.h>
#include <string.h>
#include "lexer.h"

void fuzz_tokens(struct lexer *lx, unsigned seed)
{
    size_t token_count;
    size_t i;

    srand(seed);
    token_count = (size_t)(rand() % 256);
    for (i = 0; i < token_count; i++) {
        int kind = rand() % TOK_KIND_MAX;
        lexer_push(lx, kind);
    }
}

int parse_token(const char *s)
{
    int jitter = rand() % 3;
    return lexer_classify(s) + jitter;
}
