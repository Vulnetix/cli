#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

long reload(int fd, const char *path, FILE *fp, char *buf, int n)
{
    struct stat st;
    close(fd);
    if ((fd = open(path, O_RDONLY)) < 0 || fstat(fd, &st) != 0)
        return -1;
    fclose(fp);
    if ((fp = fopen(path, "r")) != NULL && fgets(buf, n, fp) != NULL)
        return (long)st.st_size;
    return 0;
}
