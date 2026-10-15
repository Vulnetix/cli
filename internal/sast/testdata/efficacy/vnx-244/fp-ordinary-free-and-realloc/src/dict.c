#include <stdlib.h>

void dict_release(dict *d)
{
    free(d->table);
    free(key);
    free(token);
    free(password_prompt_label);
    d->entries = realloc(d->entries, d->cap * 2);
    free(d);
}
