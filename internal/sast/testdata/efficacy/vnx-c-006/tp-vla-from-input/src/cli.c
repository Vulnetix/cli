#include <stdlib.h>
#include <string.h>

void parse_args(int argc, char **argv)
{
    int count = atoi(argv[1]);
~>    int values[count];

    for (int i = 0; i < count; i++)
        values[i] = 0;
}

void echo_name(const char *name)
{
~>    char copy[strlen(name) + 1];
    strcpy(copy, name);
}
