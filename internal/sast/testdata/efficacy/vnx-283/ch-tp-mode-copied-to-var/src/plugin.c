#include <dlfcn.h>
#include <sys/stat.h>

void *plugin_open(const char *so_path)
{
    struct stat sb;
    if (lstat(so_path, &sb) == -1)
        return NULL;
    mode_t mode = sb.st_mode;
~>    if (mode & (S_IWGRP | S_IWOTH))
        return NULL;
    return dlopen(so_path, RTLD_NOW);
}
