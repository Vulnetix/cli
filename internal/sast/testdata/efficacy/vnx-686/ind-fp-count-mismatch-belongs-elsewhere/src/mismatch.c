#include <stdio.h>

void g(const char *user)
{
    printf("a %s b %d\n", user);
    printf("%s\n", user, user);
}
