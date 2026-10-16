#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include "file.h"

int file_open_all(struct file *f, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fclose(fp);
        return -1;
    }
    void *map = mmap(NULL, f->len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        fclose(fp);
        return -1;
    }
    ssize_t n = read(fd, f->head, sizeof f->head);
    if (n < 0)
        return -1;
    int rc = pthread_create(&f->worker, NULL, file_worker, f);
    if (rc != 0)
        return rc;
    f->fp = fp;
    f->map = map;
    return 0;
}
