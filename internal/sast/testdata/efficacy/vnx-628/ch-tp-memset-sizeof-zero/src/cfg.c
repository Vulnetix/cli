#include <string.h>

struct config { int a; char name[32]; };

void reset(struct config *cfg, char *buf, size_t n) {
~>    memset(cfg, sizeof(*cfg), 0);
~>    memset(buf, n, 0);
    memset(buf, 0, n);
}
