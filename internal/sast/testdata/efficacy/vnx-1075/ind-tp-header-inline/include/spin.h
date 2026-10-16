static inline int spin_until(volatile int *flag)
{
    int tries = 0;
again:
    if (!*flag) {
        tries++;
        cpu_relax();
~>        goto again;
    }
    return tries;
}
