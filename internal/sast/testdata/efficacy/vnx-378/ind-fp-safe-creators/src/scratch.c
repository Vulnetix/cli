#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int make_scratch(char *out, size_t n)
{
    char tmpl[] = "/tmp/scratchXXXXXX";
    char dirtmpl[] = "/tmp/workdirXXXXXX";
    int fd = mkstemp(tmpl);
    int fd2;
    FILE *anon;

    if (fd < 0)
        return -1;
    fd2 = mkostemp(dirtmpl, O_CLOEXEC);
    if (fd2 >= 0)
        close(fd2);
    if (mkdtemp(dirtmpl) == NULL)
        return -1;
    anon = tmpfile();
    if (anon)
        fclose(anon);
    fchmod(fd, 0600);
    snprintf(out, n, "%s", tmpl);
    return fd;
}
