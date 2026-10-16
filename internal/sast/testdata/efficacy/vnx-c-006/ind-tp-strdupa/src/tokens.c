#define _GNU_SOURCE
#include <string.h>

int count_fields(const char *input)
{
~>    char *work = strdupa(input);
    int n = 0;
    for (char *tok = strtok(work, ","); tok != NULL; tok = strtok(NULL, ","))
        n++;
    return n;
}
