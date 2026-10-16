#include <stdlib.h>
#include <string.h>

char **alloc_slots(void)
{
    const char *raw = getenv("WORKER_SLOTS");
    unsigned long slots = strtoul(raw ? raw : "4", NULL, 10);
    size_t bytes = slots * sizeof(char *);
~>    char **table = malloc(bytes);
    memset(table, 0, bytes);
    return table;
}
