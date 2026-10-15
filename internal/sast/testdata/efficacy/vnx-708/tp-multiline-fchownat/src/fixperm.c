#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

int fix(int dirfd, char **argv) {
    unsigned long owner = strtoul(argv[1], NULL, 10);
~>    return fchownat(dirfd,
                    "data.db",
                    (uid_t)owner,
                    (gid_t)-1,
                    AT_SYMLINK_NOFOLLOW);
}
