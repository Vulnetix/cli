#include <stdlib.h>

struct config { int verbose; };

void reset(void)
{
    struct config cfg;
    cfg.verbose = 0;
~>    free(&cfg);
}
