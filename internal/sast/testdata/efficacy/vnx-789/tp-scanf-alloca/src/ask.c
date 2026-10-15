#include <stdio.h>
#include <alloca.h>

void ask(void)
{
    int items;
    scanf("%d", &items);
~>    char *tmp = alloca(items);
    tmp[0] = 0;
}
