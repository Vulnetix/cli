#include <sys/stat.h>
#include <stdio.h>

int make_helper(const char *path)
{
~>    if (chmod(path, S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        perror("chmod");
        return -1;
    }
    return 0;
}
