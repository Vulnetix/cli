#include <cstdlib>
#include <string>

struct Entry {
    char *data;
    size_t len;
    Entry *next;
};

void drop(Entry *e)
{
    std::free(e->data);
~>    e->data[0] = '\0';
}

int consume(Entry *entry)
{
    delete entry;
~>    return entry->len > 0 ? 1 : 0;
}

void drain(int *values)
{
    delete[] values;
~>    values[0] = -1;
}
