#include <stdlib.h>
void drop(struct S *s)
{
    free(s->token);
    s->token = NULL;
    free(s->token);
    int fd = open_it();
    close(fd);
    fd = -1;
    if (fd != -1) close(fd);
}
