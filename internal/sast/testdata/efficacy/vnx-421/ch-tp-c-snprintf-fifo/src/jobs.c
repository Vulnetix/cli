#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int open_job_fifo(void)
{
	char fifo_path[64];
	snprintf(fifo_path, sizeof(fifo_path), "/tmp/jobs.%d.fifo", (int)getpid());
~>	if (mkfifo(fifo_path, 0600) < 0)
		return -1;
	return 0;
}
