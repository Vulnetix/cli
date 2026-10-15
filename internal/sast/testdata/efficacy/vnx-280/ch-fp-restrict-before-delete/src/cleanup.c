#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

void remove_work_dir(const char *dir)
{
	/* the extractor left it read-only: make it removable */
	chmod(dir, 0700);
	if (rmdir(dir) != 0)
		perror("rmdir");
}
