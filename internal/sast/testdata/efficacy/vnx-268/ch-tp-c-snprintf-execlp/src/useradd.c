#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int add_user(const char *name)
{
    char buf[256];
    snprintf(buf, sizeof buf, "sudo /usr/sbin/useradd %s", name);
~>    return system(buf);
}

int run_as(const char *user, const char *prog)
{
~>    return execlp("sudo", "sudo", "-u", user, prog, (char *)NULL);
}
