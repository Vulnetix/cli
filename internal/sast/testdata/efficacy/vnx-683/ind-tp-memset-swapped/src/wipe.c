#include <string.h>

struct sess { unsigned char key[32]; unsigned char iv[16]; };

void sess_free(struct sess *s)
{
~>    memset(s->key, sizeof(s->key), 0);
~>    memset(s->iv, 0xff, 0);
}
