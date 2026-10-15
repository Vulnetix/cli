#include <mutex>

static std::mutex stats_mu;
static long hits;

void record()
{
    if (stats_mu.try_lock()) {
        ++hits;
        stats_mu.unlock();
    }
}

void record_blocking()
{
    stats_mu.lock();
    ++hits;
    stats_mu.unlock();
}

bool record_soon()
{
    bool ok = stats_mu.try_lock();
    if (!ok)
        return false;
    ++hits;
    stats_mu.unlock();
    return true;
}
