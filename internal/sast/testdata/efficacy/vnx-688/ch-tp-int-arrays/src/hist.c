#include <string.h>

static int counts[64];
static int totals[16];

void reset(void)
{
~>    memset(totals, 0, sizeof(counts));
    memset(counts, 0, sizeof counts);
}
