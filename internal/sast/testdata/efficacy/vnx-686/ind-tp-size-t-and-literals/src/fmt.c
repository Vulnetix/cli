#include <stdio.h>
#include <string.h>

void show(const char *name, char *buf)
{
~>    printf("name is %d bytes\n", strlen(name));
~>    printf("status %s\n", 404);
~>    sprintf(buf, "%d items", "ten");
~>    printf("%f\n", 1);
}
