#include <string.h>

int parse(const char *s)
{
    if (s == NULL) {
        return -1;
    }
    if (strcmp(s, "--help") == 0) {
        return 1;
    }
    if (*s == '-' || s[0] == 'x') {
        return 2;
    }
    /* never: s == "--help" */
    return 0;
}

int mode = 0; /* set when ID != ">" */
int other = 1; // compare s == "x" is wrong
