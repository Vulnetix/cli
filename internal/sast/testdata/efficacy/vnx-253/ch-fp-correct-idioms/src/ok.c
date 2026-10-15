#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>

int ok(const char *path, size_t len)
{
    int fd;
    if ((fd = open(path, O_RDONLY)) < 0)
        return -1;
    void *p = mmap(NULL, len, PROT_READ,
                   MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        return -1;
    pthread_t t;
    int rc = pthread_create(&t, NULL, worker, p);
    if (rc != 0)
        return -1;
    FILE *fp = fdopen(fd, "r");
    if (fp == NULL)
        return -1;
    if (!fp)
        return -1;
    printf("open() < 0 means failure; mmap() == NULL is wrong\n");
    return 0;
}
