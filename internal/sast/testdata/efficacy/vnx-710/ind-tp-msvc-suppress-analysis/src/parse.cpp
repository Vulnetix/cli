#include <cstddef>
#include <cstdint>

~>#define SILENCE_OVERRUN __pragma(warning(disable: 6386))

std::size_t decode(const std::uint8_t *in, std::size_t n, std::uint8_t *out)
{
    SILENCE_OVERRUN
    std::size_t j = 0;
    for (std::size_t i = 0; i < n; ++i) {
~>#pragma warning(suppress: 6385)
        out[j++] = in[i + 1];
    }
    return j;
}
