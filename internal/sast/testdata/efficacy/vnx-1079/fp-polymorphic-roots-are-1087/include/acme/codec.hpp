#pragma once
#include <cstddef>

namespace acme {

class Codec
{
public:
    [[nodiscard]] virtual std::size_t encode(const char* in, char* out) const = 0;
    [[nodiscard]] virtual std::size_t decode(const char* in, char* out) const = 0;
};

}  // namespace acme
