#include <stdio.h>
#include "db.h"

static struct db_handle db;

void server_boot(const char *path)
{
~>    if (!db_init(&db, path)) {
        perror("db_init");
    }
    listen_forever(&db);
}
