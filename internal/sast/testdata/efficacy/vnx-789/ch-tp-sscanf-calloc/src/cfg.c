#include <stdio.h>
#include <stdlib.h>

struct entry *load_entries(const char *line)
{
    size_t count;
    if (sscanf(line, "entries=%zu", &count) != 1)
        return NULL;
~>    return calloc(count, sizeof(struct entry));
}
