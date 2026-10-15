#include <stdlib.h>
#include <string.h>

#define BUFSIZE 4096

int main(int argc, char **argv)
{
    int port = atoi(argv[1]);
    char *buf = malloc(BUFSIZE);
    char *name = malloc(strlen(argv[2]) + 1);
    int n_items = 4;
    int *items = calloc(n_items, sizeof(int));
    printf("malloc(atoi(argv[1])) would be unsafe on port %d\n", port);
    /* char *p = malloc(atoi(s)); */
    free(items);
    free(name);
    free(buf);
    return 0;
}
