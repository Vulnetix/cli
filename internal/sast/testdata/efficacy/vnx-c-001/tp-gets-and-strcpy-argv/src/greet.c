#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char line[128];
    char name[32];

    if (argc < 2)
        return 1;
~>    strcpy(name, argv[1]);
    printf("hello %s, say something: ", name);
~>    if (gets(line) == NULL)
        return 1;
    puts(line);
    return 0;
}
