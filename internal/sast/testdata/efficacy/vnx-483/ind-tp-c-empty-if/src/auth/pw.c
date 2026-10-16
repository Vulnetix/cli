#include <string.h>
#include "auth.h"

int check_password(const char *pw, const char *expected)
{
~>    if (strcmp(pw, expected) != 0);
    {
        return -1;
    }
    return 0;
}
