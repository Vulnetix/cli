#include <stdio.h>
#include <fcntl.h>

/* Never use tmpnam() or mktemp(): they only return a name. */
// mktemp(buf) is racy
static const char *HELP = "do not call tmpnam(buf) or mktemp(buf)";

int open_log(const char *dir)
{
    puts(HELP);
    return open(dir, O_WRONLY | O_CREAT | O_APPEND, 0600);
}

int open_private_tmp(void)
{
    return open("/tmp/agent.state", O_RDWR | O_CREAT, 0600);
}

int open_group_tmp(void)
{
    return open("/tmp/agent.group", O_RDWR | O_CREAT, 0640);
}
