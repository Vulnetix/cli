#include <string.h>

void digest_init(void)
{
    unsigned char state[16];
    memset(state, 0, sizeof(state));
    use_state(state);
}

void digest_copy(unsigned char *state, const unsigned char *from)
{
    memcpy(state, from, 16);
}
