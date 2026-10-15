#include <dirent.h>
#include <stdio.h>
#include <pthread.h>

int scan(const char *path)
{
    FILE *fp;
    DIR *d;
~>    if ((fp = fopen(path, "r")) < 0) {
        return -1;
    }
~>    if ((d = opendir(path)) == -1)
        return -1;
    pthread_t t;
~>    if (pthread_create(&t, NULL, worker, d) < 0)
        return -1;
    return 0;
}
