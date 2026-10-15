#include <stdio.h>

/* chown(argv[1], atoi(argv[2]), -1) would let the caller pick an owner. */
// chown(getenv("FILE"), 0, 0);
void usage(void) {
    fprintf(stderr, "usage: chown(argv[1]) is not supported\n");
}
