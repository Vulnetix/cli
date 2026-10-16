#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s n m\n", argv[0]);
        return 1;
    }
~>    int *table = (int *)malloc(atoi(argv[1]) * sizeof(int));
    int nent = 0;
    read(0, &nent, sizeof nent);
    size_t bytes = nent * sizeof(long);
~>    long *e = malloc(bytes);
    return table && e ? 0 : 2;
}
