#include <gtk/gtk.h>

void show_notice(GtkWindow *parent, const char *msg)
{
    GtkWidget *dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
                                               "%s", msg);
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    if (response == GTK_RESPONSE_DELETE_EVENT)
        g_debug("notice dismissed with the window close button");
    gtk_widget_destroy(dialog);
}
