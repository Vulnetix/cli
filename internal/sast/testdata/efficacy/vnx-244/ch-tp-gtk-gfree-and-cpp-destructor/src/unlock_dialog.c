#include <glib.h>
#include <string.h>

static void
on_unlock_clicked (GtkButton *button, UnlockDialog *self)
{
  gchar *passphrase = g_strdup (gtk_entry_get_text (self->entry));
  gboolean ok = keyring_unlock (self->keyring, passphrase);
  update_status (self, ok);
~>  g_free (passphrase);
}
