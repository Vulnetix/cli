#include <mutex>
#include <chrono>

static std::timed_mutex tm;
static int ticks = 0;

void tick() {
~>    tm.try_lock_for(std::chrono::milliseconds(10));
    ++ticks;
    tm.unlock();
}
