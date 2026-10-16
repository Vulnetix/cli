#include <string.h>

/* memset(s->key, sizeof(s->key), 0); wrong */
// fputs(stderr, msg);
const char *doc = "memcpy(src, dst, n) copies backwards";
void z(char *buf) { memset(buf, 0, 16); }
