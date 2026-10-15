#include <stddef.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

void zero_name(void)
{
    char name[32];
~>    for (size_t i = 0; i <= sizeof(name); i++) {
        name[i] = 0;
    }
}

int ports[8];

void reset_ports(void)
{
    int j;
~>    for (j = 0; j <= ARRAY_SIZE(ports); j++)
        ports[j] = -1;
}
