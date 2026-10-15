class Meter {
public:
    void tick() { ticks_++; }
    int value() const { return ticks_; }

private:
    int ticks_;
    double rate_;
};

namespace stats {
    int global_hits;
    void hit() { global_hits++; }
}
