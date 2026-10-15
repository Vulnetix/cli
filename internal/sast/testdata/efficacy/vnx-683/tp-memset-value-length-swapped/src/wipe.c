#include <string.h>

struct session { unsigned char key[32]; char token[64]; };

void wipe(struct session *s, char *buf, size_t n) {
~>    memset(s->key, sizeof(s->key), 0);
~>    memset(buf, n, 0);
~>    memset( s->token , 64 , '\0' );
}
