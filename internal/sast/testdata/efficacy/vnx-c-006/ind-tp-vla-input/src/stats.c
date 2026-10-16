#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    int count = atoi(argv[1]);
~>    int values[count];
    for (int i = 0; i < count; i++)
        values[i] = i * i;
    printf("%d\n", values[count - 1]);
    return 0;
}

void shout(const char *name)
{
~>    char copy[strlen(name) + 1];
    strcpy(copy, name);
    for (char *p = copy; *p; p++)
        *p = (char)toupper((unsigned char)*p);
    puts(copy);
}
