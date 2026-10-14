#include <stdlib.h>
#include <assert.h>

/* Fuzz the token parser with throwaway tokens. */
void test_parse_token(void)
{
    char token[17];
    for (int i = 0; i < 16; i++)
        token[i] = 'a' + rand() % 26;
    token[16] = '\0';
    assert(parse_token(token) == 0);
}
