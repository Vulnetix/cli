#include <stdlib.h>
#include <stdio.h>

char *dup_name(const char *name, size_t n)
{
    char *copy = malloc(n + 1);
    if (copy == NULL)
        return NULL;
    struct node *nd = calloc(1, sizeof *nd);
    if (!nd) {
        free(copy);
        return NULL;
    }
    FILE *fp = fopen(path, "r");

    if (fp == NULL) { perror("fopen"); return NULL; }
    char *tmp = malloc(n);
    assert(tmp != NULL);
    void *p = xmalloc(n);
    if ((buf = malloc(n)) == NULL) abort();
    return copy;
}

void drop(uid_t uid)
{
    if (setuid(uid) != 0)
        abort();
}
