#include <string.h>
void run(const char *arg)
{
    char local[16];
    size_t n = strlen(arg);
~>    memcpy(local, arg, n);
}
