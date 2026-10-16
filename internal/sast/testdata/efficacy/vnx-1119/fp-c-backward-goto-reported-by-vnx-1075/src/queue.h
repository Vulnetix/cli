static inline int queue_wait(struct queue *q)
{
top:
    if (!queue_ready(q))
        goto top;
    return 0;
}
