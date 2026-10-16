#include <alloca.h>
#include <string.h>

#define FRAME_BYTES 512

struct hdr { unsigned short type; unsigned short len; };

void build_frame(void)
{
    struct hdr *h = alloca(sizeof(struct hdr));
    unsigned char *frame = alloca(FRAME_BYTES);
    char *tag = alloca(16 * sizeof(char));
    memset(h, 0, sizeof(*h));
    memset(frame, 0, FRAME_BYTES);
    memset(tag, 0, 16);
    /* alloca(len) would be unbounded here; we use constants only */
}
