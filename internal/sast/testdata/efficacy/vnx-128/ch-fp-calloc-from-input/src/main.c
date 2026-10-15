#include <stdlib.h>

int main(int argc, char **argv)
{
    int n = atoi(argv[1]);
    int *a = calloc(n, sizeof(int));
    free(a);
    return 0;
}
