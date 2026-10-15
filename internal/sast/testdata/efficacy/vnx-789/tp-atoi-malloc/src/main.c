#include <stdlib.h>

int main(int argc, char **argv)
{
    int count = atoi(argv[1]);
~>    char *buf = malloc(count * sizeof(char));
    free(buf);

    long n = strtol(getenv("ROWS"), NULL, 10);
~>    int *rows = calloc(n,
                       sizeof(int));
    free(rows);
    return 0;
}
