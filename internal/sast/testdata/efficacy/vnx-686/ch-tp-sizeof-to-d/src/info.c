#include <stdio.h>

struct foo { int a; char b[40]; };

void info(void)
{
~>    printf("%d\n", sizeof(struct foo));
}
