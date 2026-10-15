#include <mutex>

void Registry::add(const Item &item)
{
    if (!mutex_.try_lock())
        return;
    items_.push_back(item);
    mutex_.unlock();
}

void Registry::flush()
{
    std::unique_lock<std::mutex> guard(mutex_, std::try_to_lock);
    if (!guard.owns_lock()) {
        return;
    }
    items_.clear();
}

void Registry::drain()
{
    std::unique_lock<std::mutex> lk{mutex_, std::try_to_lock};
    if (lk) {
        items_.clear();
    }
}
