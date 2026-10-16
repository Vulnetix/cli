#include <gtk/gtk.h>
#include "purge.h"

static void on_purge_clicked(GtkButton *button, gpointer user_data)
{
    GtkWindow *parent = GTK_WINDOW(user_data);
    GtkWidget *dialog = gtk_message_dialog_new(parent,
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_QUESTION,
                                               GTK_BUTTONS_OK_CANCEL,
                                               "Purge the audit log?");
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    switch (response) {
~>    case GTK_RESPONSE_YES:
        audit_log_purge();
        break;
    default:
        break;
    }
    gtk_widget_destroy(dialog);
}
