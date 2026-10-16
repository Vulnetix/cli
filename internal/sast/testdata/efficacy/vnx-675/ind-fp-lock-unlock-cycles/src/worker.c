#include <pthread.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int jobs;

void work(void)
{
    pthread_mutex_lock(&mu);
    jobs++;
    pthread_mutex_unlock(&mu);
    /* pthread_mutex_unlock(&mu); twice would be UB */
    pthread_mutex_lock(&mu);
    jobs--;
    pthread_mutex_unlock(&mu);
}

void cleanup(FILE *fp)
{
    fclose(fp);
    fp = NULL;
    if (fp) fclose(fp);
}
