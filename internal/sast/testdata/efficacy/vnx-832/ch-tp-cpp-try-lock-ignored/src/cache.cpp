#include <chrono>
#include <mutex>
#include <string>

static std::mutex cache_mu;
static std::timed_mutex refresh_mu;
static std::string cached;

void refresh(const std::string &v)
{
    cache_mu.try_lock();
    cached = v;
~>    cache_mu.unlock();
}

void slow_refresh(const std::string &v)
{
    refresh_mu.try_lock_for(std::chrono::milliseconds(50));
    cached = v;
~>    refresh_mu.unlock();
}
