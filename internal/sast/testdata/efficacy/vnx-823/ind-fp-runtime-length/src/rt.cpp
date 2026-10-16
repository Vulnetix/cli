#include <cstdint>
#include <cstring>
#include <vector>

struct frame { uint16_t kind; uint16_t size; };

void parse(const uint8_t *data, size_t len)
{
    std::vector<uint8_t> out(len);
    for (size_t i = 0; i < out.size(); ++i)
        out[i] = data[i];
    const uint8_t *body = data + sizeof(frame);
    const frame *f = reinterpret_cast<const frame *>(data);
    const uint8_t *tail = body + f->size;
    (void)tail;
}
