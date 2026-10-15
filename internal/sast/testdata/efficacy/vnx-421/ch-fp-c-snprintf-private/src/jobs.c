#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int open_job_fifo(const char *rundir)
{
	char fifo_path[64];
	char note[64];
	snprintf(note, sizeof(note), "/tmp/jobs.%d.log", (int)getpid());
	snprintf(fifo_path, sizeof(fifo_path), "%s/jobs.fifo", rundir);
	if (mkfifo(fifo_path, 0600) < 0)
		return -1;
	snprintf(fifo_path, sizeof(fifo_path), "/run/jobs/%d.fifo", (int)getpid());
	return mkfifo(fifo_path, 0600);
}
