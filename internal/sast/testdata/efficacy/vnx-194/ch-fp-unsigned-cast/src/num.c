#include <ctype.h>

int all_digits(const char *s)
{
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s))
            return 0;
    }
    return 1;
}
