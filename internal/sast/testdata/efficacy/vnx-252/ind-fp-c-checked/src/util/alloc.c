#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "alloc.h"

char *dup_or_null(const char *s)
{
    size_t n = strlen(s);
    char *p = malloc(n + 1);
    if (!p)
        return NULL;
    memcpy(p, s, n + 1);
    return p;
}

int open_log(const char *path, FILE **out)
{
    FILE *fp = fopen(path, "a");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }
    *out = fp;
    return 0;
}

void *table_new(size_t n)
{
    void *t = xmalloc(n);
    memset(t, 0, n);
    return t;
}

int become(uid_t uid, gid_t gid)
{
    if (setgid(gid) != 0)
        return -1;
    if (setuid(uid) != 0)
        return -1;
    return 0;
}
