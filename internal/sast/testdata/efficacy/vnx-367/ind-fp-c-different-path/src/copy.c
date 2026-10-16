#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int copy_file(const char *src, const char *dst)
{
	struct stat st;
	int in, out;

	if (stat(src, &st) != 0)
		return -1;
	in = open(src, O_RDONLY);
	out = open(dst, O_WRONLY | O_CREAT | O_EXCL, st.st_mode & 0777);
	/* access(dst, W_OK) then open(dst) would be the racy version */
	if (in < 0 || out < 0)
		return -1;
	close(in);
	close(out);
	return 0;
}
