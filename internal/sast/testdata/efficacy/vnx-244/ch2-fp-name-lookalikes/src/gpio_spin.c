#include <stdlib.h>

void teardown(struct ctx *c)
{
    free(c->spin);
    free(c->keymap);
    free(c->pin_table_len_buf);
    free(c->pwdir);
    delete_cache(c->secret_count);
    free(c->hotkeys);
}
