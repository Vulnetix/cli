#include <stdio.h>
#include <stdlib.h>

void read_all(FILE *f)
{
    char *line;
    while ((line = next_line(f)) != NULL) {
        handle(line);
        free(line);
    }
    free(line);
}

void drain(struct queue *q)
{
    struct item *it;
    for (it = pop(q); it; it = pop(q)) {
        free(it->data);
    }
    free(it->data);
}
