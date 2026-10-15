#include <gtk/gtk.h>

static void confirm_disable_firewall(GtkWindow *parent)
{
    GtkWidget *dialog = gtk_message_dialog_new(parent,
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_WARNING,
                                               GTK_BUTTONS_YES_NO,
                                               "Disable the firewall?");
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
~>    if (response == GTK_RESPONSE_OK) {
        firewall_disable();
    }
    gtk_widget_destroy(dialog);
}
