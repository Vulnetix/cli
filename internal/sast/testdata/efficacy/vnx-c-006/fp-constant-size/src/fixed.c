#include <alloca.h>

#define FRAME_BYTES 512

struct hdr { int a; };

void fixed(void)
{
    struct hdr *h = alloca(sizeof(struct hdr));
    char *frame = alloca(FRAME_BYTES);
    int *pair = alloca(2 * sizeof(int));
    char name[64];
    char dup[] = "abc";
    char *lit = strdupa("constant");
    use(h, frame, pair, name, dup, lit);
}
