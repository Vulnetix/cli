#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>

int ok(const char *path, int fd, size_t len)
{
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return -1;
    ssize_t n = read(fd, buf, len);
    if (n < 0)
        return -1;
    size_t got = fread(buf, 1, len, f);
    if (got < len)
        return -1;
    void *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (p == MAP_FAILED)
        return -1;
    int rc = pthread_create(&t, NULL, fn, NULL);
    if (rc != 0)
        return -1;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    if (write(fd, buf, len) < 0)
        return -1;
    char *line = malloc(len);
    if (!line)
        return -1;
    size_t sz = strlen(path);
    if (sz < 0) { }
    return 0;
}
