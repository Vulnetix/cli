#include <stdlib.h>

void configure_runtime(void)
{
~>    setenv("LD_LIBRARY_PATH",
           "./lib:/usr/lib/acme", 1);
~>    setenv(
        "PATH",
        "tools:/usr/bin", 1);
}
