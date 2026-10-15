#include <cstdint>

class Frame {
public:
    void reset();
private:
    uint8_t *pixels_;
    int width_;
};

void Frame::reset() {
    delete[] pixels_;
    width_ = 0;
    log_reset(width_);
~>  delete [] pixels_;
}
