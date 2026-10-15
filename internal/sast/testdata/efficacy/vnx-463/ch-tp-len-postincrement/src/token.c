#include <string.h>

void push_char(char *word, char ch)
{
    size_t len = strlen(word);
~>    word[len++] = ch;
    emit(word);
}
