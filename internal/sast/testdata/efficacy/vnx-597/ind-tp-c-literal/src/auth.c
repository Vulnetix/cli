#include <stdio.h>
#include <string.h>

int check(const char *input, const char *cmd)
{
~>    if (input == "letmein") {
        return 1;
    }
~>    if (cmd != "quit")
        return 2;
    return 0;
}
