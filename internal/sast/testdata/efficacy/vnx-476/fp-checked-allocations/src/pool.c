#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *dup_name(const char *name, size_t len)
{
    char *p = malloc(len + 1);
    if (p == NULL)
        return NULL;
    memcpy(p, name, len);
    return p;
}

char *dup2(const char *name)
{
    char *q = strdup(name);
    if (!q) return NULL;
    q[0] = 'x';
    return q;
}

int load(char *line, int size)
{
    FILE *f;
    if ((f = fopen("/etc/app.conf", "r")) == NULL)
        return -1;
    fgets(line, size, f);
    fclose(f);
    return 0;
}

void env(char *dst)
{
    const char *home = getenv("HOME");
    strcpy(dst, home ? home : "/tmp");
}

void assert_alloc(size_t n)
{
    int *v = calloc(n, sizeof(int));
    assert(v);
    v[0] = 1;
    free(v);
}

void unused_then_free(size_t n)
{
    char *buf = malloc(n);
    free(buf);
}
