#include <stdlib.h>
#include <stdio.h>

int show_target(const char *link)
{
    char base[64], resolved[256];
    snprintf(base, sizeof base, "%s", "target");
~>    if (realpath(link, resolved) == NULL) {
        perror("realpath");
        return 1;
    }
    printf("%s -> %s\n", base, resolved);
    return 0;
}
