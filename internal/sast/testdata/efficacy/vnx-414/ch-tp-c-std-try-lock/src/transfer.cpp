#include <mutex>
#include <threads.h>

struct Account { std::mutex m; long balance; };

void transfer(Account &a, Account &b, long amount)
{
~>    std::try_lock(a.m, b.m);
    a.balance -= amount;
    b.balance += amount;
    a.m.unlock();
    b.m.unlock();
}

static mtx_t journal_mtx;
static pthread_spinlock_t spin;

void journal(int v)
{
~>    mtx_trylock(&journal_mtx);
    record(v);
    mtx_unlock(&journal_mtx);
~>    pthread_spin_trylock(&spin);
    counter++;
    pthread_spin_unlock(&spin);
}
