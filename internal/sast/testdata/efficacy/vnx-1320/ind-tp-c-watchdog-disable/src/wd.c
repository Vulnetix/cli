#include <sys/ioctl.h>
#include <linux/watchdog.h>
#include <fcntl.h>

void stop_wd(void) {
    int fd = open("/dev/watchdog", O_WRONLY);
    int flags = WDIOS_DISABLECARD;
~>    ioctl(fd, WDIOC_SETOPTIONS, &flags);
}

void magic_close(int fd) {
~>    write(fd, "V", 1);
}
