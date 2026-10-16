#include <stdlib.h>

struct slot {
    void *data;
    unsigned long used;
};

static struct slot *pool;
static size_t pool_len;

int pool_resize_from_env(void)
{
    const char *env = getenv("WORKER_POOL_SIZE");
    if (env == NULL) {
        return 0;
    }
    size_t n = strtoul(env, NULL, 10);
~>    struct slot *grown = (struct slot *)realloc(pool, n * sizeof(struct slot));
    if (grown == NULL) {
        return -1;
    }
    pool = grown;
    pool_len = n;
    return 0;
}

int *make_table(char **argv)
{
~>    int *table = (int *)malloc(atoi(argv[1]) * sizeof(int));
    return table;
}
