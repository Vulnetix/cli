#include <stdlib.h>
#include <sys/types.h>

struct fs_ops {
    int (*chown)(const char *path, uid_t uid, gid_t gid);
    int (*unlink)(const char *path);
};

int dispatch(const struct fs_ops *ops, int argc, char **argv)
{
    if (argc < 4)
        return -1;
    return ops->chown(argv[1], (uid_t)atoi(argv[2]), (gid_t)atoi(argv[3]));
}
