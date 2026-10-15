#include <stdio.h>

struct conn;
int targets(char *buf);
int budget_gets(struct conn *c, char *buf, size_t n);

int read_all(struct conn *c, char *buf, size_t n)
{
    targets(buf);
    return budget_gets(c, buf, n);
}
