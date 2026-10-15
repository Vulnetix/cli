#include <gtk/gtk.h>

static void on_reset(GtkWidget *parent)
{
    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(parent),
        GTK_DIALOG_MODAL, GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
        "Reset preferences?");
    switch (gtk_dialog_run(GTK_DIALOG(dialog))) {
~>    case GTK_RESPONSE_OK:
        reset_preferences();
        break;
    default:
        break;
    }
    gtk_widget_destroy(dialog);
}
