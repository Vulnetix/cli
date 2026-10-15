#include <inttypes.h>
#include <stdio.h>

void stat_line(char *buf, uint64_t n, const char *label)
{
~>    sprintf(buf, "%" PRIu64 " %s", n, label);
}
