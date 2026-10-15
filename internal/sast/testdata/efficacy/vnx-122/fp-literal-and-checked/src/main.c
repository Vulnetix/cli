#include <stdlib.h>
#include <string.h>

char *banner(void)
{
    char *b = malloc(32);
    strcpy(b, "welcome");
    return b;
}

char *checked(const char *in)
{
    char *b = malloc(64);
    if (strlen(in) >= 64)
        return NULL;
    strcpy(b, in);
    return b;
}

char *bounded(const char *in)
{
    char *b = malloc(64);
    strncpy(b, in, 63);
    b[63] = '\0';
    sprintf(b, "%d items", 4);
    sprintf(b, "%.40s", in);
    return b;
}
