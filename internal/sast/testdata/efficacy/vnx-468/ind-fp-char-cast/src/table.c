#include <stddef.h>

struct entry { long key; long value; };

struct entry *entry_at(void *base, size_t i)
{
    char *p = (char *)base + i * sizeof(struct entry);
    return (struct entry *)p;
}
