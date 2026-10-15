#include <stdio.h>

void rotate(const char *path)
{
    FILE *fp = fopen(path, "r");
    copy(fp);
    fclose(fp);
    fp = fopen(path, "w");
    truncate_file(fp);
    fclose(fp);

    int fd = open(path, O_RDONLY);
    close(fd);
    fd = open(path, O_WRONLY);
    close(fd);
}
