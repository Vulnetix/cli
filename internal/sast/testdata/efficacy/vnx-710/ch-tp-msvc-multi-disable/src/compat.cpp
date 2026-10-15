#include <cstring>

~>#pragma warning(disable: 4100 4996)
void copy_name(char *dst, const char *src) {
    strcpy(dst, src);
}
~>#pragma warning(suppress : 6386)
void fill(char *buf) { buf[16] = 0; }
