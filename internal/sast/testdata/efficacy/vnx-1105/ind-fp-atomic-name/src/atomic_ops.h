#ifndef ATOMIC_OPS_H
#define ATOMIC_OPS_H

static inline void barrier(void)
{
    asm volatile("" ::: "memory");
}

#endif
