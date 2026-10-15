#include <stdlib.h>

int parse_port(const char *s) {
    int p = atoi(s);
    long l = atol(s);
    double d = atof(s);
    return p > 0 && p < 65536 ? p : (int)(l + d);
}
