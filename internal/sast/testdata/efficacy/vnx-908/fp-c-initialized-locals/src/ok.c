#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

int parse(const char *s, long *out);
int get_error(char **err);
int compute(void);

long file_size(const char *p)
{
    struct stat st;
    if (stat(p, &st) == 0)
        return st.st_size;
    return -1;
}

long read_value(const char *s)
{
    long v;
    if (parse(s, &v) < 0)
        return -1;
    return v;
}

int run(void)
{
    int n = 0;
    int ret;
    int i;
    char *err;
    int x;
    ret = compute();
    for (i = 0; i < 10; i++)
        n += i;
    if (get_error(&err))
        puts(err);
    scanf("%d", &x);
    return ret + n + x;
}

size_t width(void)
{
    int cols;
    cols = sizeof(cols) * 8;
    return (size_t)cols;
}
