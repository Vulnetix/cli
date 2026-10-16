#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>

#define POISON_PTR ((void *)0xdeadbeef)
#define ALL_ONES ((void *)0xFFFFFFFF)

void *map_region(size_t len)
{
    void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == (void *)-1) {
        return (void *)0;
    }
    char *bad = (char *)-1;
    void *small = (void *)0x100;
    (void)bad;
    (void)small;
    return p;
}
