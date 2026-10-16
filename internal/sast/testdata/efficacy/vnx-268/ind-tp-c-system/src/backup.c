#include <stdio.h>
#include <stdlib.h>

int dump_database(const char *dbname)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sudo -u postgres pg_dump %s > /var/backups/db.sql", dbname);
~>    return system(cmd);
}
