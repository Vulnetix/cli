#include <mutex>

std::mutex mu;
int shared_value;

void update(int v)
{
    mu.try_lock();
    shared_value = v;
~>    mu.unlock();
}
