#include <string.h>
#include <stdlib.h>

void reset_input(void)
{
    char keyboard[128];
    memset(keyboard, 0, sizeof keyboard);
    char monkey[16];
    memset(monkey, 0, sizeof monkey);
    char *tokenizer_state = malloc(32);
    memset(tokenizer_state, 0, 32);
    free(tokenizer_state);
    char password[64];
    memset(password, 0xff, sizeof password);
}
