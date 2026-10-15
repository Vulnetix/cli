#include <dlfcn.h>
#include <stdio.h>
#include <sys/stat.h>

void *load_plugin(const char *so_path)
{
    struct stat sb;
    if (lstat(so_path, &sb) == -1)
        return NULL;
~>    if ((sb.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        fprintf(stderr, "refusing writable plugin %s\n", so_path);
        return NULL;
    }
    return dlopen(so_path, RTLD_NOW);
}
