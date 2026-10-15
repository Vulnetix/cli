#include <mutex>

void Registry::add(const Item &item)
{
~>  mutex_.try_lock();
    items_.push_back(item);
    mutex_.unlock();
}

void Registry::flush()
{
~>  std::unique_lock<std::mutex> guard(mutex_, std::try_to_lock);
    items_.clear();
}

void Registry::touch()
{
~>  state->timed.try_lock_for(std::chrono::milliseconds(5));
    state->touched = true;
}
