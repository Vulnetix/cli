#include <stdlib.h>

static unsigned int isn;

unsigned int next_isn(void)
{
~>    isn += rand() % 4096;
    return isn;
}
