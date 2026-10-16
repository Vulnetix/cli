#include <sys/ioctl.h>
#include <linux/watchdog.h>
#include <termios.h>

void feed(int fd) {
    ioctl(fd, WDIOC_KEEPALIVE, 0);
    int t = 30;
    ioctl(fd, WDIOC_SETTIMEOUT, &t);
}

void tty(int fd) {
    int n;
    ioctl(fd, TIOCMGET, &n);
}
