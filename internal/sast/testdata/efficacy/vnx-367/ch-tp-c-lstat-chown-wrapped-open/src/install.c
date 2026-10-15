#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int prepare(const char *tmpfile, uid_t uid, gid_t gid)
{
	struct stat sb;
	if (lstat(tmpfile, &sb) != 0 || !S_ISREG(sb.st_mode))
		return -1;
~>	if (chown(tmpfile, uid, gid) != 0)
		return -1;
~>	return open(tmpfile,
	            O_RDWR | O_APPEND);
}
