#include <sqlite3.h>
#include <stdio.h>
#include <windows.h>

int run_migration(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
~>    sqlite3_close(db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "migration failed: %s\n", sqlite3_errmsg(db));
        sqlite3_free(err);
    }
    return rc;
}

BOOL append_marker(HANDLE hFile)
{
    DWORD written = 0;
~>    CloseHandle(hFile);
    return WriteFile(hFile, "END", 3, &written, NULL);
}
