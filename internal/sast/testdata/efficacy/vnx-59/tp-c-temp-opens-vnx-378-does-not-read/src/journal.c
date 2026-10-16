#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

/* Owner-only modes and update opens: no wide permission, but the name can
 * still be a planted symbolic link. */
void journal_rotate(void)
{
~>    FILE *cur = fopen("/tmp/journal.cur", "r+");
~>    int fd = open("/tmp/journal.idx", O_WRONLY | O_CREAT | O_TRUNC, 0600);
~>    int nfd = creat("/var/tmp/journal.next", 0600);
    fclose(cur);
    close(fd);
    close(nfd);
}
