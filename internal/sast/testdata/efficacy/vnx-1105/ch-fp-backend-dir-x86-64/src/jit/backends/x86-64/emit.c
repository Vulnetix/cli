#include "emit.h"

void emit_fence(struct jit *j)
{
    __asm__ __volatile__("mfence" ::: "memory");
    jit_put(j, 0x0f);
}
