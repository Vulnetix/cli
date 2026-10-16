#include <string.h>

int count_opts(char *argline)
{
    int n = 0;
    char *tok = strtok(argline, " ");
    while (tok) {
        if (strchr(tok, ':')) {
~>            char *name = strtok(tok, ":");
            (void)name;
        }
        n++;
        tok = strtok(NULL, " ");
    }
    return n;
}
