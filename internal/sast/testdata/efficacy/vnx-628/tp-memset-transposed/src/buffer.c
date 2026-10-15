#include <string.h>

struct session { char key[32]; int n; };

void wipe(struct session *s, char *buf, size_t len)
{
~>	memset(s->key, sizeof(s->key), 0);
~>	memset(buf, len, 0);
~>	memset( &s->n , 0xff , 0 );
	memset(buf, 0, len);
}
