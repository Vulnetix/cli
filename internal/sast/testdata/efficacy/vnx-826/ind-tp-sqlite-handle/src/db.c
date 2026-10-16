#include <sqlite3.h>
#include <stdio.h>

void run(sqlite3 *db)
{
    sqlite3_exec(db, "select 1", 0, 0, 0);
~>    sqlite3_close(db);
    fprintf(stderr, "%s\n", sqlite3_errmsg(db));
}
