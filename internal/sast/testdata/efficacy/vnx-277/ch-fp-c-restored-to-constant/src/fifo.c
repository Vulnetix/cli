#include <sys/stat.h>
#include <sys/types.h>

int make_fifo(const char *path)
{
	int rc;

	umask(0);
	rc = mkfifo(path, 0620);
	umask(022);
	return rc;
}
