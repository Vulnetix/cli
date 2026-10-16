#include <gtk/gtk.h>

gboolean confirm_delete(GtkWindow *parent, const char *name)
{
    GtkWidget *dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_WARNING, GTK_BUTTONS_NONE,
                                               "Delete %s?", name);
    gtk_dialog_add_buttons(GTK_DIALOG(dialog),
                           "_Keep", GTK_RESPONSE_NO,
                           "_Delete", GTK_RESPONSE_YES,
                           NULL);
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    return response == GTK_RESPONSE_YES;
}
