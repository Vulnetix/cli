#include <string.h>
#include <stdio.h>

void greet(const char *who)
{
    char *p;
~>    strcpy(p, who);
    printf("hello\n");
}
