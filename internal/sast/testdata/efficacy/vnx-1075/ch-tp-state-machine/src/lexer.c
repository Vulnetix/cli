#include <ctype.h>

int count_words(const char *p)
{
    int words = 0;
    int inword = 0;
next:
    switch (*p) {
    case '\0':
        return words;
    default:
        if (isspace((unsigned char)*p)) {
            inword = 0;
        } else if (!inword) {
            inword = 1;
            words++;
        }
    }
    p++;
~>    goto next;
}
