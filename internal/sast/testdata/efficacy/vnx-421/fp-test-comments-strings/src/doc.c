#include <stdio.h>
#include <sys/un.h>

/* Never do this: mkfifo("/tmp/x.fifo", 0600); */
// strcpy(addr.sun_path, "/tmp/x.sock");
void help(void)
{
    puts("do not call mkfifo(\"/tmp/x.fifo\") or bind to /tmp");
    puts("CreateNamedPipe needs FIRST_PIPE_INSTANCE");
}
