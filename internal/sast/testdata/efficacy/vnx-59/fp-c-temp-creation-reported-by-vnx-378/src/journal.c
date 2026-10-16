#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

/* Each of these creates a fixed name in a shared temporary directory with
 * permissions other users can use: VNX-378 reports them. */
void journal_open(int id)
{
    FILE *log = fopen("/tmp/journal.log", "a");
    FILE *snap = fopen("/var/tmp/journal.snap", "wb");
    int fd = open("/tmp/journal.lock", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char *state = "/dev/shm/journal.state";
    int sfd = open(state, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH);
    char spool[128];
    snprintf(spool, sizeof spool, "/var/tmp/journal-%d.spool", id);
    FILE *sp = fopen(spool, "w");
    fclose(log);
    fclose(snap);
    fclose(sp);
    (void)fd;
    (void)sfd;
}
