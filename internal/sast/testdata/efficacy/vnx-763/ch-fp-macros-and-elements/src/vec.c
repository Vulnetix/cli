#include <stdlib.h>

#define VEC_FREE(v) free((v)->data)

struct vec {
    int *data;
    int len;
};

void vec_destroy(struct vec *v)
{
    VEC_FREE(v);
    v->data = NULL;
}

void release_all(void **ptrs, int n)
{
    for (int i = 0; i < n; i++)
        free(ptrs[i]);
    free(ptrs);
    // free(&local) would be wrong here
    puts("free(buffer) done");
}
