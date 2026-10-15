#include <unistd.h>

int join_wheel(void)
{
~>	if (setregid(-1, 0) < 0)
		return -1;
	return 0;
}
