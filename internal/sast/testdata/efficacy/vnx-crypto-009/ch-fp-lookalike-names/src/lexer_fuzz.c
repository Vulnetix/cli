#include <stdlib.h>

/* Fuzzing helpers: random choices that are not secrets. */
void fuzz_tokens(struct lexer *lx)
{
    int token_count = rand() % 64;
    int keyframe = rand() % 30;
    size_t key_index = rand() % lx->table_size;
    int max_key_len = 8 + rand() % 24;
    for (int i = 0; i < token_count; i++) {
        lexer_emit(lx, rand() % TOKEN_KIND_MAX);
    }
    (void)keyframe; (void)key_index; (void)max_key_len;
}
