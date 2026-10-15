#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>

int arm_watchdog(void)
{
	int fd = open("/dev/watchdog", O_WRONLY);
	int opt = WDIOS_ENABLECARD; // not WDIOS_DISABLECARD
	int timeout = 30;

	ioctl(fd, WDIOC_SETOPTIONS, &opt);
	ioctl(fd, WDIOC_SETTIMEOUT, &timeout);
	ioctl(fd, WDIOC_KEEPALIVE, 0);
	write(fd, "\0", 1);
	return fd;
}
