#include <stdio.h>

int main(int argc, char **argv)
{
~>    if (argc > 1 && argv[1] == "--help") {
        puts("usage: tool [file]");
        return 0;
    }
    return 1;
}
