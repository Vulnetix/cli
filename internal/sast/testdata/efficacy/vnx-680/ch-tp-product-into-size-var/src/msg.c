#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

struct entry { uint64_t key; uint64_t val; };

struct entry *read_entries(int fd)
{
    uint32_t nent;
    if (read(fd, &nent, sizeof nent) != sizeof nent)
        return NULL;
    size_t bytes = nent * sizeof(struct entry);
~>    struct entry *e = malloc(bytes);
    return e;
}
