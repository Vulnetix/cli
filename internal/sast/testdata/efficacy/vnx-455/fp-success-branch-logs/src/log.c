#include <stdio.h>

void boot(void)
{
    if (init_logging() == 0)
        printf("logging ready\n");
    if (cache_init() != NULL) {
        puts("cache initialised");
    }
}
