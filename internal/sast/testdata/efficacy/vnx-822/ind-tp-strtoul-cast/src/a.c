#include <stdlib.h>
int main(int argc, char **argv)
{
~>    char *p = (char *)strtoul(argv[1], NULL, 16);
    return *p;
}
