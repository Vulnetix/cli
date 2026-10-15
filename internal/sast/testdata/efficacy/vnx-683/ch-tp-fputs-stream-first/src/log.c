#include <stdio.h>

void warn(const char *msg)
{
~>    fputs(stderr, msg);
}
