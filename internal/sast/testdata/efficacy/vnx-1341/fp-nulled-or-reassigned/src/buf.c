#include <stdlib.h>

void cycle(char *p, char *q, int fd)
{
    free(p);
    p = NULL;
    free(p);

    free(q);
    q = malloc(32);
    free(q);

    close(fd);
    fd = open("x", 0);
    close(fd);
}
