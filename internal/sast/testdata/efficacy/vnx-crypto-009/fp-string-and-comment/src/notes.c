#include <stdio.h>

void explain(void)
{
    // token[i] = alphabet[rand() % 62];  -- the old, predictable way
    /* session_id = rand(); */
    printf("never derive a token from rand(): it is predictable\n");
    const char *token_help = "token = rand() is not acceptable";
    puts(token_help);
}
