#include <string.h>

struct frame {
    unsigned short len;
};

unsigned short frame_len(const char *data)
{
    char buf[64];
    memcpy(buf, data, sizeof buf);
    const struct frame *f = (const struct frame *)buf;
    return f->len;
}
