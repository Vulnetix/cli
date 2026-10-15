#ifndef QUEUE_H
#define QUEUE_H

static inline void queue_barrier(void)
{
~>    __asm__ volatile ("" ::: "memory");
}

#endif
