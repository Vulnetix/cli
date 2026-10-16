#include <stdio.h>
#include <unistd.h>

void run_job(const char *job_name)
{
    char script[512];
    snprintf(script, sizeof(script), "/opt/jobs/bin/%s --nightly", job_name);
    if (fork() == 0) {
~>        execl("/bin/sh", "sh", "-c", script, (char *)NULL);
        _exit(127);
    }
}
