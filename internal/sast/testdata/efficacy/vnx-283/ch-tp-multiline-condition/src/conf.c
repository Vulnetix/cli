#include <stdio.h>
#include <sys/stat.h>

FILE *open_conf(const char *path)
{
    struct stat st;

    if (stat(path, &st) < 0)
        return NULL;
~>    if ((st.st_mode &
         (S_IWGRP | S_IWOTH)) != 0) {
        fprintf(stderr, "refusing writable %s\n", path);
        return NULL;
    }
    return fopen(path, "r");
}
