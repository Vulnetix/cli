#include <errno.h>
#include <sys/stat.h>

static const char *spool_dir = "/var/spool/agent";

const char *open_spool(void)
{
	if (mkdir(spool_dir, 0700) != 0 && errno == EACCES) {
~>		spool_dir = "/tmp";
	}
	return spool_dir;
}

const char *open_log_dir(const char *dir)
{
~>	if (mkdir(dir, 0700) != 0 && errno == EPERM) dir = "/tmp";
	return dir;
}
