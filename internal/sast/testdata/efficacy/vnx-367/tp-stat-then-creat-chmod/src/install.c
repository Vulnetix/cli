#include <fcntl.h>
#include <sys/stat.h>

int install_key(const char *keyfile)
{
	struct stat st;
	if (stat(keyfile, &st) == 0) {
		return -1;
	}
~>	int fd = creat(keyfile, 0600);
	return fd;
}

int fix_mode(const char *dir)
{
	struct stat st;
	if (lstat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
~>		chmod(dir, 0700);
	}
	return 0;
}

FILE *fresh_log(const char *logname)
{
	struct stat sb;
	if (stat(logname, &sb) != 0)
~>		return fopen(logname, "w");
	return NULL;
}
