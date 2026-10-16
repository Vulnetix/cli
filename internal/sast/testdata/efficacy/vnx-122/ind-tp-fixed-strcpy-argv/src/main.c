#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATH_BUF 128

int main(int argc, char **argv)
{
    char *path = (char *)malloc(PATH_BUF);
    if (!path)
        return 1;
    if (argc < 2) {
        fprintf(stderr, "usage: %s FILE\n", argv[0]);
        return 2;
    }
~>    strcpy(path, argv[1]);
    printf("opening %s\n", path);
    free(path);
    return 0;
}
