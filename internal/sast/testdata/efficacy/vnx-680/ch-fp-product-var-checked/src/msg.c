#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

void *read_entries(int fd)
{
    uint32_t nent;
    read(fd, &nent, sizeof nent);
    if (nent > 1024)
        return NULL;
    size_t bytes = nent * 16;
    void *e = malloc(bytes);
    size_t other = 8 * 4;
    void *f = malloc(other);
    free(f);
    return e;
}
