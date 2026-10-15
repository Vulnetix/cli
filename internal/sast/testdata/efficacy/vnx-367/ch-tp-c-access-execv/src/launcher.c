#include <unistd.h>

int launch(const char *prog, char *const args[])
{
	if (access(prog, X_OK) == 0)
~>		execv(prog, args);
	return -1;
}
