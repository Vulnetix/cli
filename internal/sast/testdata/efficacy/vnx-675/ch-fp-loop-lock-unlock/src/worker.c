#include <pthread.h>

void drain(struct pool *p)
{
    for (int i = 0; i < p->n; i++) {
        pthread_mutex_lock(&p->m);
        p->done++;
        pthread_mutex_unlock(&p->m);
    }
    fclose(p->in);
    fclose(p->out);
    close(p->fds[0]);
    close(p->fds[1]);
}
