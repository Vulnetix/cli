#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s PATH UID GID\n", argv[0]);
        return 2;
    }
    uid_t owner = (uid_t)atoi(argv[2]);
    gid_t group = (gid_t)atoi(argv[3]);

~>    if (chown(argv[1], owner, group) != 0) {
        perror("chown");
        return 1;
    }
    return 0;
}
