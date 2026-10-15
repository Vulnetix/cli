#include <stdio.h>
#include <unistd.h>

int file_size(FILE *fp, int fd) {
    fseek(fp, 0, SEEK_END);
~>    int size = ftell(fp);
~>    unsigned int end = lseek(fd, 0, SEEK_END);
    int pos;
~>    pos = (int)ftello(fp);
    return size + end + pos;
}
