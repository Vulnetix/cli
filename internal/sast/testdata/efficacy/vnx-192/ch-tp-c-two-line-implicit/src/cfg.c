#include <stdlib.h>
#include <stdint.h>

struct cfg { uint16_t port; };

void load(struct cfg *c, const char *val)
{
    long n = strtol(val, NULL, 10);
~>    c->port = (uint16_t)n;
}
