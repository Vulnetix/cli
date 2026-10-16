#include <sys/stat.h>
#include <unistd.h>

int check_authorized_keys(const char *path, uid_t expected)
{
    struct stat st;

    if (stat(path, &st) != 0)
        return -1;
    if (st.st_uid != expected && st.st_uid != 0)
        return -1;
    if (st.st_mode & (S_IWGRP | S_IWOTH))
        return -1;
    return 0;
}
