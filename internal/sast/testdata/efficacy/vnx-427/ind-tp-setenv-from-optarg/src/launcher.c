#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int opt;
    while ((opt = getopt(argc, argv, "L:v")) != -1) {
        switch (opt) {
        case 'L':
~>            setenv("LD_LIBRARY_PATH", optarg, 1);
            break;
        case 'v':
            verbose = 1;
            break;
        default:
            usage(argv[0]);
            return 2;
        }
    }
    execv("/opt/acme/bin/acme-worker", argv + optind);
    return 127;
}
