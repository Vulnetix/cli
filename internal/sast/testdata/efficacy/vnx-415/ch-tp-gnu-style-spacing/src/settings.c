#include <glib.h>

gboolean
settings_load (Settings *self, const gchar *file)
{
  gchar *contents = NULL;
  gsize length = 0;

  if (!g_file_get_contents (file, &contents, &length, NULL))
    return FALSE;

  settings_parse (self, contents, length);
  g_free (contents);
  settings_emit_changed (self);
~>  g_free (contents);
  return TRUE;
}
