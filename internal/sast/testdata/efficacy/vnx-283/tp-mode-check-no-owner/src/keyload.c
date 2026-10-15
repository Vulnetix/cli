#include <stdio.h>
#include <sys/stat.h>

int load_private_key(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
~>    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr, "%s: permissions too open\n", path);
        return -1;
    }
    return read_key(path);
}

int trust_plugin_dir(const char *dir) {
    struct stat sb;
    lstat(dir, &sb);
~>    if ((sb.st_mode&S_IWOTH) != 0)
        return 0;
    return 1;
}
