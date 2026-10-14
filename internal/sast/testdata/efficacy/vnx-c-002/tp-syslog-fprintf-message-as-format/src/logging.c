#include <stdio.h>
#include <syslog.h>

void log_failure(const char *peer_message, FILE *out)
{
~>    syslog(LOG_ERR, peer_message);
~>    fprintf(out, peer_message);
~>    dprintf(2, peer_message);
}

void log_reason(const char *reason, int id)
{
    char line[512];

    snprintf(line, sizeof(line), "client %d: %s\n", id, reason);
~>    printf(line);
~>    printk(line);
}
