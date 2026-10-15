#include <stdlib.h>

int table_load(struct table *t, FILE *fp, size_t rows)
{
    struct row *items = calloc(rows,
                               sizeof(struct row));
    if (!items)
        return ENOMEM;

    for (size_t i = 0; i < rows; i++) {
        if (read_row(fp, &items[i]) != 0) {
~>            return EIO;
        }
    }
    t->items = items;
    t->count = rows;
    return 0;
}
