#include <sqlite3.h>
#include <stdio.h>

static sqlite3 *db;

void store_boot(const char *path)
{
    int rc;
    rc = sqlite3_initialize();
~>    if (rc != SQLITE_OK)
        fprintf(stderr, "sqlite3_initialize: %s\n", sqlite3_errstr(rc));
    sqlite3_open(path, &db);
}
