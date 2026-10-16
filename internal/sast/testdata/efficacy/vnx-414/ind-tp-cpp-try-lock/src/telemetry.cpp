#include <mutex>
#include <vector>

class Telemetry {
public:
    void record(int sample) {
~>        mu_.try_lock();
        samples_.push_back(sample);
        mu_.unlock();
    }

    void flush() {
~>        std::unique_lock<std::mutex> guard(mu_, std::try_to_lock);
        sent_ += samples_.size();
        samples_.clear();
    }

private:
    std::mutex mu_;
    std::vector<int> samples_;
    size_t sent_ = 0;
};
