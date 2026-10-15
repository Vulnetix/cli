#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

int main(int argc, char **argv)
{
    int c;
    while ((c = getopt(argc, argv, "L:")) != -1) {
        if (c == 'L') {
~>            setenv("LD_LIBRARY_PATH", optarg, 1);
        }
    }
    if (argc > 1) {
~>        setenv("PATH", argv[1], 1);
    }
    return execvp("worker", argv);
}
