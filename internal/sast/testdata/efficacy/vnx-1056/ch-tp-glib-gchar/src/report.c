#include <glib.h>

~>gchar *report_line(GString *out, const gchar *fmt, ...) {
    va_list args;
    gchar *line;
    va_start(args, fmt);
    line = g_strdup_vprintf(fmt, args);
    va_end(args);
    g_string_append(out, line);
    return line;
}
