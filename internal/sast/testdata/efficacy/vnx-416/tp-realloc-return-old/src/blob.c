#include <glib.h>

guint8 *blob_resize(guint8 *blob, gsize size)
{
    guint8 *resized = g_realloc(blob, size);
    log_resize(size);
~>  return blob;
}
