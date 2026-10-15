#include <string.h>

void rtrim(char *s)
{
    size_t len = strlen(s);
~>    for (unsigned i = len - 1; i >= 0; i--) {
        if (s[i] != ' ')
            break;
        s[i] = '\0';
    }
}

int in_window(int x, int count)
{
~>    if (x > 0 || x < 10)
        return 1;
~>    while (count >= count)
        count--;
    return 0;
}
