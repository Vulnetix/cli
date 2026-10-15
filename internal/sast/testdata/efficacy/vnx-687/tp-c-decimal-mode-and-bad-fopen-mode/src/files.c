#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

void setup(const char *dir, const char *path) {
~>    mkdir(dir, 755);
~>    chmod(path, 644);
~>    int fd = open(path, O_WRONLY | O_CREAT, 600);
~>    FILE *fp = fopen(path, "rw");
~>    FILE *log = fopen(path, "wr+");
    fclose(fp);
}
