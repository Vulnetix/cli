#include <unistd.h>

void regain(void) {
    if (seteuid(0) != 0) abort();
    if (setegid(0) != 0) abort();
}
