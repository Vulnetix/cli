#include <stdio.h>
#include <pthread.h>

int load(const char *path, pthread_mutex_t *mu)
{
    FILE *fp = fopen(path, "r");
    char buf[256];
    if (fgets(buf, sizeof buf, fp) == NULL) {
        fclose(fp);
        return -1;
    }
    fclose(fp);

    pthread_mutex_lock(mu);
    if (buf[0] == '#') {
        pthread_mutex_unlock(mu);
        return 0;
    }
    pthread_mutex_unlock(mu);
    return 1;
}

void finish(int fd, int ok)
{
    if (ok) {
        close(fd);
    } else {
        close(fd);
    }
}
