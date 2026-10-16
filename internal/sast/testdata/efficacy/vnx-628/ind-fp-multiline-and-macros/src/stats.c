#include <stdio.h>
#include <inttypes.h>

void dump_stats(FILE *out, const char *name, uint64_t bytes, uint64_t pkts)
{
    fprintf(out, "%s: %" PRIu64 " bytes, %" PRIu64 " packets\n", name, bytes, pkts);
    fprintf(out,
            "%s: rx=%" PRIu64 " tx=%" PRIu64 "\n",
            name,
            bytes,
            pkts);
    printf("%s %s\n",
           name, "done");
}
