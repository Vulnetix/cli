#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    gid_t group = 0;
    int c;
    while ((c = getopt(argc, argv, "g:")) != -1) {
        switch (c) {
        case 'g':
            group = (gid_t)atoi(optarg);
            break;
        }
    }
~>    chown("/var/lib/app/data", 0, group);
    return 0;
}
