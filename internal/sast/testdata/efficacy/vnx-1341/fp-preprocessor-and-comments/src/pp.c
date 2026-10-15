#include <stdlib.h>

void release(char *p)
{
#ifdef USE_POOL
    pool_free(p);
#else
    free(p);
#endif
    /* free(p); here would be a double free */
    // free(p);
}

void destroy(struct obj *o)
{
    g_object_unref(o);
    g_object_unref(o);
}
