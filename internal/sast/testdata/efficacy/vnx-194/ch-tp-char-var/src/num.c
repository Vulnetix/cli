#include <ctype.h>

int all_digits(const char *s)
{
    for (; *s; s++) {
        char c = *s;
~>        if (!isdigit(c))
            return 0;
    }
    return 1;
}
