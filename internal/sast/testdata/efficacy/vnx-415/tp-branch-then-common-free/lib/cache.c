#include <stdlib.h>

void cache_evict(struct cache *c, struct entry *e)
{
    if (e->expired) {
        g_free(e->payload);
        c->bytes -= e->size;
    }
    unlink_entry(c, e);
~>  g_free(e->payload);
    free(e);
}
