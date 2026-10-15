void work(struct pool *p)
{
    pthread_mutex_lock(&p->mu);
    take(p);
    pthread_mutex_unlock(&p->mu);
    process(p);
    pthread_mutex_lock(&p->mu);
    give(p);
    pthread_mutex_unlock(&p->mu);
}

void wait_ready(struct pool *p)
{
    pthread_mutex_lock(&p->mu);
    while (!p->ready)
        pthread_cond_wait(&p->cv, &p->mu);
    pthread_mutex_unlock(&p->mu);
}
