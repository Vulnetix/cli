#include <unistd.h>

int open_device(const char *dev)
{
~>	setegid(0);
~>	setreuid(-1, 0);
~>	setresuid(-1, 0, -1);
	return open_raw(dev);
}
