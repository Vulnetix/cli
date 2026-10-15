#include <stdlib.h>

const char *default_args[] = {"--quiet", "--fast", NULL};

void cleanup(void)
{
~>    free(default_args);
~>    free("unused");
}
