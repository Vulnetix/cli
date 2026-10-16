#include <stdlib.h>
#include <string.h>

void make_session_token(char *token, size_t len, unsigned long user_id)
{
    size_t i;
~>    srand((unsigned) (user_id % 997));
    for (i = 0; i + 1 < len; i++) {
        token[i] = "0123456789abcdef"[rand() & 15];
    }
    token[len - 1] = '\0';
}
