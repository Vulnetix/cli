#include <stdlib.h>
#include <string.h>

char *dup_string(const char *s)
{
    char *copy = malloc(strlen(s) + 1);
    if (copy == NULL)
        return NULL;
    strcpy(copy, s);
    return copy;
}

int set_hostname(char dst[64], const char *src)
{
    if (strlen(src) >= 64)
        return -1;
    strcpy(dst, src);
    return 0;
}

struct node { char key[32]; };

void clone_node(struct node *dst, const struct node *src)
{
    strcpy(dst->key, src->key);
}
