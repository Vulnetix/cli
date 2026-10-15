#include <cstdint>

namespace hal {

void enable()
{
~>    auto *ctrl = reinterpret_cast<std::uint32_t *>(0x1F000000);
~>    char *vram = (char *)
        0xB8000;
    *ctrl = 1;
    vram[0] = 'A';
}

}
