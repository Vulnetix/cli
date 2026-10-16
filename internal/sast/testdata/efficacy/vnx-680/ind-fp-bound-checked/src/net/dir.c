#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_ENTRIES 4096

struct entry {
    uint64_t inode;
    char name[256];
};

struct entry *read_directory(int fd)
{
    uint32_t nent;
    if (read(fd, &nent, sizeof nent) != sizeof nent) {
        return NULL;
    }
    if (nent > MAX_ENTRIES) {
        return NULL;
    }
    struct entry *e = malloc(nent * sizeof(struct entry));
    return e;
}

void *alloc_rows(const char *arg)
{
    size_t rows = strtoull(arg, NULL, 10);
    if (rows == 0 || rows > SIZE_MAX / sizeof(long)) {
        return NULL;
    }
    return malloc(rows * sizeof(long));
}
