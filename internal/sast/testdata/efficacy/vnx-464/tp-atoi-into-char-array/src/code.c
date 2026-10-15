#include <stdlib.h>
#include <string.h>

void build_code(char **argv)
{
    char code[8];
    code[0] = 'A';
    code[1] = 'B';
~>    code[2] = atoi(argv[1]);
    code[3] = '\0';
    printf("%s\n", code);
}
