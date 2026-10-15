#include <stdlib.h>

static char *names[16];

int set_name(const char *arg, char *value)
{
    int idx = atoi(arg);
~>    if (idx >= 16)
        return -1;
    names[idx] = value;
    return 0;
}

long get_entry(char **argv, long *table, long size)
{
    long i = strtol(argv[1], NULL, 10);
~>    if (i < size) {
        return table[i];
    }
    return 0;
}
