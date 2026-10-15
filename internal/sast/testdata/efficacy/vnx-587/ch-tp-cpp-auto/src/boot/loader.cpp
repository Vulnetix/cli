#include <cstdint>

void *load_base()
{
~>    auto sram = reinterpret_cast<std::uint8_t *>(0x20000000);
    sram[0] = 0;
~>    return (void *)0x7fff0000;
}
