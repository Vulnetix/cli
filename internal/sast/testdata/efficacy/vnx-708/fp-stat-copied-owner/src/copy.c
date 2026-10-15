#include <sys/stat.h>
#include <unistd.h>

int preserve(const char *src, const char *dst) {
    struct stat st;
    if (stat(src, &st) != 0)
        return -1;
    return chown(dst, st.st_uid, st.st_gid);
}

struct fs_ops { int (*chown)(const char *, int, int); };

int via_ops(struct fs_ops *ops, char **argv) {
    return ops->chown(argv[1], 0, 0);
}
