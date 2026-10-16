#include <mutex>

void Flusher::flush() {
    std::unique_lock<std::mutex> lk(mu_, std::try_to_lock);
    if (!lk.owns_lock()) {
        return;
    }
    pending_ = 0;
    if (mu2_.try_lock()) {
        other_ = 0;
        mu2_.unlock();
    }
}
