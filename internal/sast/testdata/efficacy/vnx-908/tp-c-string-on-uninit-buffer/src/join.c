#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *join(const char *a, const char *b)
{
    char *out = malloc(strlen(a) + strlen(b) + 1);
    if (out == NULL)
        return NULL;
~>    strcat(out, a);
    strcat(out, b);
    return out;
}

void greet(const char *who)
{
    char msg[128];
~>    strncat(msg, who, sizeof(msg) - 1);
    puts(msg);
}

size_t label_len(void)
{
    char label[32];
~>    return strlen(label);
}
