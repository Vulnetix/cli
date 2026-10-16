#include <string.h>

int check(const char *input, char *buf)
{
    if (strcmp(input, "letmein") == 0) return 1;
    if (strncmp(buf, "GET ", 4) == 0) return 2;
    if (buf[0] == 'x') return 3;
    if (input == NULL) return 0;
    /* input == "secret" is a bug */
    return 4;
}
