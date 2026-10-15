#include <stdio.h>

int main(int argc, char **argv)
{
~>    if (argc > 1 && argv[1] == "--help") {
        puts("usage");
    }
    const char *mode = argv[0];
~>    while (mode != "quit")
        break;
    return 0;
}
