#include <stdio.h>

int handle(int cmd, int *state)
{
	switch (cmd) {
	case 1:
		*state = 10;
		break;
~>	case 2:
		*state = 20;
		log_cmd(cmd);
	case 3:
		*state = 30;
		break;
	default:
		return -1;
	}
	return 0;
}
