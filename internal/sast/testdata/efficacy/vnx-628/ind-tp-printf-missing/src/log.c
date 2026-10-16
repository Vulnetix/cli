#include <stdio.h>

void report(const char *user, int code)
{
~>    printf("user %s failed with %d\n", user);
    (void)code;
}
