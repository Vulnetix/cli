#include <string.h>

void copy_name(char *dst, const char *src) {
~>    strcpy(dst, src); // FIXME: possible buffer overflow, src is unchecked
}
