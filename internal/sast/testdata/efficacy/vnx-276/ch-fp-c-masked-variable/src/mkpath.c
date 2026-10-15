#include <sys/stat.h>
#include <sys/types.h>

int make_public_dir(const char *path)
{
	mode_t old = umask(0);
	mode_t mode = 0777;

	umask(old);
	mode &= ~old;
	return chmod(path, mode);
}
