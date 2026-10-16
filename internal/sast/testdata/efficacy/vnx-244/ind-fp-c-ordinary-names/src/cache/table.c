#include <stdlib.h>
#include "table.h"

/* entries are freed with free(entry->key); never free(password) here */
void table_destroy(struct table *t)
{
    for (size_t i = 0; i < t->len; i++) {
        free(t->entries[i].key);
        free(t->entries[i].value);
    }
    free(t->entries);
    free(t->token);
    free(t);
}

void lexer_free(struct lexer *lx)
{
    free(lx->spinner);
    free(lx->keyboard_map);
    free(lx->pinned);
}
