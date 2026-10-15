#include <stdlib.h>

struct config {
    int port;
    char *host;
};

void reset(void)
{
    struct config cfg;
    int counter = 0;
    load(&cfg);
~>    free(&cfg);
~>    free( &counter );
~>    free((void *)&cfg);
}
