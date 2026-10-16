#include <string.h>
#include <stdint.h>

struct session {
    uint8_t key[32];
    uint8_t iv[16];
};

void session_wipe(struct session *s)
{
~>    memset(s->key, sizeof(s->key), 0);
~>    memset(s->iv, sizeof s->iv, '\0');
}
