#include <unistd.h>

void sandbox(const char *jail) {
    chdir("/var/tmp");
~>    chroot(jail);
    drop_privileges();
}

void other(void) {
    chdir("/");
}
