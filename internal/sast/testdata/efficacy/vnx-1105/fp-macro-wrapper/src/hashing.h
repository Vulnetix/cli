#ifndef HASHING_H
#define HASHING_H

#if defined(__GNUC__)
#  define HASH_COMPILER_GUARD(var) __asm__("" : "+r" (var))
#  define HASH_BARRIER() \
      __asm__ __volatile__("" ::: "memory")
#else
#  define HASH_COMPILER_GUARD(var) ((void)0)
#  define HASH_BARRIER() ((void)0)
#endif

static inline unsigned mix(unsigned v)
{
    v *= 0x9E3779B1u;
    HASH_COMPILER_GUARD(v);
    return v;
}

#endif
