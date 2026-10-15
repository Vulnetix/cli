#include <stdint.h>
#include <string.h>

#define PAGE_SIZE 0x1000
#define BAD_PTR ((void *)-1)
#define POISON ((void *)0xdeadbeef)

static const uintptr_t base = 0x40021000;

void clear(char *buf, char *p)
{
    memset(buf, 0, 0x1000);
    char *q = p + 0x1000;
    int x = (int)0x1000;
    long y = (long) 0x40000000;
    void *z = (void *)0;
    void *all = (void *)0xFFFFFFFF;
    if (q == (char *)0x2000) {
        return;
    }
    (void)z; (void)all; (void)x; (void)y;
}
