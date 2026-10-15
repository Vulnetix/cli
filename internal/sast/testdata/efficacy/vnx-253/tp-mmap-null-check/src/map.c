#include <sys/mman.h>

void *map_file(int fd, size_t len)
{
    void *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
~>    if (p == NULL)
        return NULL;
    char *q = (char *)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
~>    if (!q) return NULL;
    return p;
}
