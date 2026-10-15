#include <pthread.h>

struct ctx { int id; };

static void *worker(void *arg) {
    struct ctx *c = (struct ctx *)arg;
    return (void *)(long)c->id;
}

void timer_cb(unsigned long arg) {
    struct ctx *c = (struct ctx *)arg;
    c->id++;
}
