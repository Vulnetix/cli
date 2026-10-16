#include <string.h>
#include <unistd.h>

void remove_lock(const char *base)
{
	char lock[64] = "/var/run/";

~>	strncat(lock, base, sizeof(lock) - strlen(lock) - 1);
	unlink(lock);
}
