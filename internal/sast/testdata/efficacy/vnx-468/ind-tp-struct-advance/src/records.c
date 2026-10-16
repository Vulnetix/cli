#include <stddef.h>

struct record {
    int id;
    char name[32];
};

void walk(struct record *table, size_t count)
{
    struct record *r = table;
    for (size_t i = 0; i < count; i++) {
        r->id = (int)i;
~>        r += sizeof(struct record);
    }
}
