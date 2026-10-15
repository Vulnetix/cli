#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>

int stop_watchdog(void)
{
	int fd = open("/dev/watchdog0", O_WRONLY);
	int flags = WDIOS_DISABLECARD;

	if (fd < 0)
		return -1;
~>	ioctl(fd, WDIOC_SETOPTIONS, &flags);
~>	write(fd, "V", 1);
	close(fd);
	return 0;
}
