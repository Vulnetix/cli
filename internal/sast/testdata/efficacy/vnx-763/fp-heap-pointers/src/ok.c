#include <stdlib.h>

void ok(size_t n)
{
    char *buf = malloc(n);
    char **list = calloc(n, sizeof(char *));
    struct node *head = make_node();
    free(buf);
    free(list);
    free(head);
    free(&buf[0]);
    free(*list);
}

void other(void)
{
    char path[64];
    use(path);
}

void third(char *path)
{
    free(path);
}

int is_null(int *vals, size_t index)
{
    return vals[index] == 0;
}

void drop(int *vals)
{
    delete_all(vals);
    free(vals);
}

void zero(int *vals, int i)
{
    if (i)
        vals[i] = 1;
    else vals[i] = 0;
    free(vals);
}
