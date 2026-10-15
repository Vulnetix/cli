#include <stdlib.h>

struct ops { int (*chown)(const char *, int, int); };

int safe_chown_check(const char *p);

int run(struct ops *o, char **argv) {
    const char *p = argv[1];
    if (safe_chown_check(p)) {
        return o->chown(p, 0, 0);
    }
    return 0;
}
