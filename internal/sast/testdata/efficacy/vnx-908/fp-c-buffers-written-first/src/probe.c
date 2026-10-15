#include <stdio.h>
#include <string.h>

int is_tsc(FILE *cs)
{
    char buf[32];
    if (cs == NULL || fgets(buf, sizeof(buf), cs) == NULL || strncmp(buf, "tsc", 3) != 0)
        return 0;
    return 1;
}
