#include <stdlib.h>

int main(int argc, char **argv)
{
    unsigned long n = strtoul(argv[1], NULL, 10);
~>    int *a = (int *) malloc(sizeof(int) * n);
    a[0] = 1;
    return 0;
}
