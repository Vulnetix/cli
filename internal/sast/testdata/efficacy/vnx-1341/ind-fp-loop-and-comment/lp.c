#include <stdlib.h>
void free_all(char **v, int n)
{
    for (int i = 0; i < n; i++) {
        free(v[i]);
    }
    free(v);
    /* free(v); again would be a double free */
    obj_unref(o);
    obj_unref(o);
}
