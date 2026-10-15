#include <fcntl.h>
#include <linux/watchdog.h>
#include <sys/ioctl.h>
#include <unistd.h>

void stop_watchdog(void)
{
	int fd = open("/dev/watchdog", O_WRONLY);
	int flags = WDIOS_DISABLECARD;

~>	ioctl(fd, WDIOC_SETOPTIONS, &flags);
~>	write(fd, "V", 1);
	close(fd);
}
