#include <string.h>

int parse(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--help") == 0)
        return 1;
    if (argv[1][0] == '-')
        return 2;
    if ((argc & 1) == 0)
        return 3;
    return 0;
}
