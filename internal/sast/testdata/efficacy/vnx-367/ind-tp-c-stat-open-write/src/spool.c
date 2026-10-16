#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int open_spool(const char *spool_path, uid_t owner)
{
	struct stat st;

	if (stat(spool_path, &st) != 0 || st.st_uid != owner)
		return -1;
	if (!S_ISREG(st.st_mode))
		return -1;
~>	return open(spool_path, O_WRONLY | O_TRUNC);
}
