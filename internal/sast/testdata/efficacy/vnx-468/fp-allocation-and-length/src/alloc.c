#include <stdlib.h>
#include <string.h>

int *make_table(size_t n)
{
    int *table = malloc(n * sizeof(int));
    memset(table, 0, n * sizeof(*table));
    size_t bytes = n * sizeof(int) + sizeof(long);
    table = realloc(table, bytes + sizeof(int));
    return table;
}

size_t frame_len(size_t count)
{
    size_t len = count + sizeof(struct header);
    return len - sizeof(long);
}
