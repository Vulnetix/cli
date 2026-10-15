#include <glib.h>
#include <sqlite3.h>

void store_shutdown(sqlite3 *db, gchar *name)
{
    g_free(name);
    sqlite3_close(db);
~>    g_free(name);
~>    sqlite3_close(db);
}
