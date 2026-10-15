#include <cstring>

void pad(char *tok)
{
    int n;
    n = std::strlen(tok);
~>    tok[n] = ' ';
    emit(tok);
}
