#include <stdio.h>
#include <stdlib.h>

void *xmalloc(size_t n);

struct col { char name[32]; int width; };

struct col *parse_header(const char *line)
{
    unsigned int ncols = 0;
    if (sscanf(line, "COLUMNS %u", &ncols) != 1)
        return NULL;
~>    struct col *cols = xmalloc(sizeof(struct col) * ncols);
    return cols;
}

char *env_buffer(void)
{
    unsigned long sz = strtoul(getenv("SCRATCH_KB"), NULL, 10);
~>    return malloc(sz * 1024 + 16);
}
