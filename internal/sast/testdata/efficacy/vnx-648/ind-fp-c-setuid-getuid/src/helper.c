#include <unistd.h>

int main(void) {
    /* setuid-root helper: give up the elevated identity again */
    if (setuid(getuid()) != 0) return 1;
    return run();
}
