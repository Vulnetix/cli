#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int load_private_key(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    if (st.st_uid != getuid() && st.st_uid != 0) {
        fprintf(stderr, "%s: bad owner\n", path);
        return -1;
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr, "%s: permissions too open\n", path);
        return -1;
    }
    return read_key(path);
}
