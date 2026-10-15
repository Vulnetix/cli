static inline void compiler_barrier(void)
{
    __asm__ __volatile__("" ::: "memory");
}
