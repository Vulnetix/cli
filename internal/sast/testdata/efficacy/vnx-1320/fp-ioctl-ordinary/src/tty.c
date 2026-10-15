#include <sys/ioctl.h>
#include <termios.h>
#include <linux/watchdog.h>

int cols(int fd)
{
	struct winsize ws;
	int timeout = 30;

	if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
		return 80;
	ioctl(fd, WDIOC_SETTIMEOUT, &timeout);
	ioctl(fd, WDIOC_KEEPALIVE, 0);
	return ws.ws_col;
}
