static inline void spin_acquire(volatile int *lock)
{
top:
	while (*lock)
		cpu_relax();
	if (__sync_lock_test_and_set(lock, 1))
~>		goto top;
}
