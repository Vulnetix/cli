#include <stdlib.h>

void parse(int *vals, char **argv, int n)
{
    int counts[8];
    for (int i = 0; i < n; i++)
        vals[i] = atoi(argv[i]);
    counts[0] = atoi(argv[0]);
}
