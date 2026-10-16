#include <stdio.h>
#include <unistd.h>

int copy(const char *a, const char *b) {
    FILE *fp = fopen(a, "r");
    if (!fp) return -1;
    if (read_header(fp) < 0) {
        fclose(fp);
        return -2;
    }
    fclose(fp);
    fp = fopen(b, "r");
    if (!fp) return -3;
    fclose(fp);
    return 0;
}

void two(int fd, int other) {
    close(fd);
    fd = -1;
    close(other);
    if (fd >= 0) close(fd);
}

void relock(pthread_mutex_t *m) {
    pthread_mutex_lock(m);
    pthread_mutex_unlock(m);
    pthread_mutex_lock(m);
    pthread_mutex_unlock(m);
}
