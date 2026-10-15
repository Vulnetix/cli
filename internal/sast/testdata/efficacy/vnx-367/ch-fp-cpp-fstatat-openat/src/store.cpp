#include <fcntl.h>
#include <sys/stat.h>
#include <string>

int open_entry(int dirfd, const std::string &name)
{
	struct stat st;
	if (fstatat(dirfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0)
		return -1;
	int fd = openat(dirfd, name.c_str(), O_WRONLY | O_NOFOLLOW);
	struct stat after;
	if (fstat(fd, &after) != 0 || after.st_ino != st.st_ino)
		return -1;
	return fd;
}
