#include <cstdint>

namespace hal {

struct TimerBlock {
    std::uint32_t ctrl;
    std::uint32_t load;
};

TimerBlock *timer0()
{
~>    auto *t = reinterpret_cast<TimerBlock *>(0x1F000000);
    return t;
}

volatile std::uint32_t *watchdog()
{
~>    return reinterpret_cast<volatile std::uint32_t *>(0x40001000ULL);
}

}  // namespace hal
