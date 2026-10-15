#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int spool(void)
{
    char tmpl[] = "/tmp/spool-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    fchmod(fd, 0600);
    chmod("/srv/public/index.html", 0644);
    FILE *t = tmpfile();
    char dir[] = "/tmp/work-XXXXXX";
    mkdtemp(dir);
    return fd;
}
