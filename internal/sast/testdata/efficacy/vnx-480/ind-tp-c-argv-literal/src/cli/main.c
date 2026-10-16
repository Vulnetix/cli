#include <stdio.h>
#include "cli.h"

int main(int argc, char **argv)
{
~>    if (argc > 1 && argv[1] == "--help") {
        usage();
        return 0;
    }
    return run(argc, argv);
}
