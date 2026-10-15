#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int keyring_store(int dirfd, const char *name, const char *data, size_t n)
{
    char tmpname[64];
    snprintf(tmpname, sizeof tmpname, ".%s.tmp", name);
    FILE *fp = fopen(tmpname, "wb");
    if (!fp)
        return -1;
    fwrite(data, 1, n, fp);
    fclose(fp);
~>    return renameat(dirfd, tmpname, dirfd, name);
}
