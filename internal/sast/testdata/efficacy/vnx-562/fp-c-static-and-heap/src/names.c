#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *format_name(const char *first, const char *last)
{
    static char buf[128];
    snprintf(buf, sizeof(buf), "%s %s", first, last);
    return buf;
}

char *dup_name(const char *s)
{
    char *copy = malloc(strlen(s) + 1);
    strcpy(copy, s);
    return copy;
}

int total(const int *v, int n)
{
    int sum = 0;
    for (int i = 0; i < n; i++) sum += v[i];
    return sum;
}

char *fill(char buf[], int n)
{
    memset(buf, 0, n);
    return buf;
}

int *ref_param(int *p)
{
    return &p[1];
}
