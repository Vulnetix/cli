#include <stdlib.h>
#include <string.h>

static char opts[16];

void parse_opts(char *spec)
{
    int i = 0;
    char *tok = strtok(spec, ",");
    while (tok != NULL && i < 15) {
~>        opts[i++] = (char)strtol(tok, NULL, 10);
        tok = strtok(NULL, ",");
    }
}
