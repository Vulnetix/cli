#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    unsigned long target_uid = 0;
    int opt;

    while ((opt = getopt(argc, argv, "o:")) != -1) {
        if (opt == 'o')
            target_uid = strtoul(optarg, NULL, 10);
    }

    int dirfd = open("/srv/data", O_DIRECTORY | O_RDONLY);
    if (dirfd < 0)
        return 1;

~>    int rc = fchownat(dirfd,
                      "incoming",
                      (uid_t)target_uid,
                      (gid_t)-1,
                      AT_SYMLINK_NOFOLLOW);
    close(dirfd);
    return rc == 0 ? 0 : 1;
}
