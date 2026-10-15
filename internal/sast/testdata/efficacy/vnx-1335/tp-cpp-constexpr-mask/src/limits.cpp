#include <cstdint>

namespace limits {
~>constexpr std::uint64_t kHuge = 1 << 48;
constexpr std::uint64_t kOk = std::uint64_t{1} << 48;
}
