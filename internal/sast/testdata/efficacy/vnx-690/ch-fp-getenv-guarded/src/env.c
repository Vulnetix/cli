#include <stdlib.h>
#include <string.h>

int debug_enabled(void)
{
    const char *v = getenv("APP_DEBUG");
    if (v == NULL || *v == '\0')
        return 0;
    return strcmp(v, "1") == 0;
}
