#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 3) {
        return 1;
    }
~>    if (lchown(argv[1], (uid_t)strtoul(argv[2], NULL, 10), (gid_t)-1) != 0) {
        return 2;
    }
    return 0;
}
