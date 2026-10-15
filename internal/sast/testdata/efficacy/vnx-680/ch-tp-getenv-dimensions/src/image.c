#include <stdlib.h>
#include <glib.h>

unsigned char *make_canvas(void)
{
    size_t w = atoi(getenv("CANVAS_WIDTH"));
~>    unsigned char *px = g_malloc(w * 4);
    return px;
}
