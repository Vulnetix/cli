#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        return 1;
    }
    uid_t uid = (uid_t)atoi(argv[2]);
    gid_t gid = (gid_t)atoi(argv[3]);
~>    if (chown(argv[1], uid, gid) != 0) {
        return 2;
    }
    return 0;
}
