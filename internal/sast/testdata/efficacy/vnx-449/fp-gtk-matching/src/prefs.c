#include <gtk/gtk.h>

static void confirm(GtkWindow *parent)
{
    GtkWidget *dialog = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_QUESTION, GTK_BUTTONS_OK_CANCEL,
                                               "Apply changes?");
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    if (response == GTK_RESPONSE_OK)
        apply();
    else if (response == GTK_RESPONSE_DELETE_EVENT)
        g_debug("closed");
    gtk_widget_destroy(dialog);
}
