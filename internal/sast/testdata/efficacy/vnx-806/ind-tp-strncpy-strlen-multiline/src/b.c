#include <string.h>
int set_path(const char *input)
{
    char buf[64];
~>    strncpy(buf,
            input,
            strlen(input));
    return buf[0];
}
