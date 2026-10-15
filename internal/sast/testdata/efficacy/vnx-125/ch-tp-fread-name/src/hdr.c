#include <stdio.h>

void show(FILE *fp)
{
    char name[32];
    fread(name, 1, sizeof(name), fp);
~>    printf("name: %s\n", name);
}
