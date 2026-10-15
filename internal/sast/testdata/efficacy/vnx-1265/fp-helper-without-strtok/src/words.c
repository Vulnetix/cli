#include <ctype.h>
#include <string.h>

static int word_len(const char *w)
{
    return (int)strlen(w);
}

int total(char *text)
{
    int sum = 0;
    char *w = strtok(text, " ");
    while (w) {
        sum += word_len(w);
        w = strtok(NULL, " ");
    }
    return sum;
}
