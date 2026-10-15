#include <string.h>

#define SPLIT_AT(sep) \
    head = s; \
    tail = strchr(s, sep)

int fields(char *s)
{
    char *ip, *port, *end;
    ip = strchr(s, ':'); if (!ip) return -1;
    port = strchr(ip, ','); if (!port) return -1;
    end = port; *end = '\0';
    return (int)(end - ip);
}

int sum_two(const int *v)
{
    int a, b;
    a = b = v[0];
    return a + b;
}

int split(char *s)
{
    char *head, *tail;
    SPLIT_AT(',');
    return (int)(tail - head);
}

int match(int n, int m)
{
    int i, j, hits;
    for (i = 0, j = 0; i != n && j != m; ++j)
        i++;
    { hits = i; goto done; }
done:
    return hits;
}
