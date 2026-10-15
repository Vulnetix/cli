#include <stdlib.h>
#include <string.h>

size_t home_len(void)
{
    const char *home = getenv("HOME");
~>    return strlen(home);
}
