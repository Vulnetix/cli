#include <sys/time.h>

#define load_atomic(src, dst) ((dst) = (src))

struct event {
    long id;
    struct event *next;
};

int flag;

int poll_paused(struct event *te)
{
    int paused;
    long id;
    struct itimerval it;
    unsigned long len;
    load_atomic(flag, paused);
    it.it_value.tv_sec = 1;
    if (te->id == 3)
        return 0;
    len = te->next->id; /* the len of the chain */
    return paused + (int)len;
}
