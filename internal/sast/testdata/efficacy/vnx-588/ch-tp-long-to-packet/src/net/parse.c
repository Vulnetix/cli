#include <stdint.h>

struct packet {
    uint8_t type;
    uint8_t flags;
};

int classify(void)
{
    long raw = 0;
    read_word(&raw);
~>    return ((struct packet *)&raw)->type;
}
