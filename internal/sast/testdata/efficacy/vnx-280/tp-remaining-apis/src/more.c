#include <fcntl.h>
#include <sys/stat.h>

void more(const char *key)
{
~>	fchmodat(AT_FDCWD, key, 0600, 0);
~>	chmod(key, S_IRWXU);
}
