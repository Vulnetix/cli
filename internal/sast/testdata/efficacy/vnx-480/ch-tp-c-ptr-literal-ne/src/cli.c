#include <string.h>

int parse(int argc, char **argv)
{
    const char *mode = argv[1];
~>    while (mode != "quit") {
        mode = next_token();
    }
~>    return (argv[2] == "-v") ? 1 : 0;
}
