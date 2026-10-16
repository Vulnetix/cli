#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    int times = atoi(argv[1]);
~>    while (times-- > 0) {
        puts("tick");
    }
    return 0;
}
