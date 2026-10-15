#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void banner(const char *who, FILE *f)
{
    char buf[64];
    char zero[16] = {0};
    char line[256];
    char *p = malloc(64);
    char *q = calloc(1, 64);
    snprintf(buf, sizeof buf, "hello %s", who);
    puts(buf);
    puts(zero);
    while (fgets(line, sizeof line, f))
        puts(line);
    if (!p)
        return;
    p[0] = '\0';
    strcat(p, who);
    strcat(q, who);
    free(p);
    free(q);
}

char *dup_name(const char *src)
{
    char *dst = malloc(strlen(src) + 1);
    if (dst == NULL)
        return NULL;
    strcpy(dst, src);
    return dst;
}
