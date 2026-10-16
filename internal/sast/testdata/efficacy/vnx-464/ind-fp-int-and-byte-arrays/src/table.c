#include <stdlib.h>

static int ports[32];
static unsigned char key[16];

void load(int i, const char *p, const char *k)
{
    ports[i] = atoi(p);
    key[i] = strtoul(k, NULL, 16);
}
