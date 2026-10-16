#include <stdio.h>

static const char *const status_formats[] = {
    "ok: %d records\n",
    "warning: %d records skipped\n",
    "error: %d records failed\n",
};

void print_status(int level, int count)
{
    const char *fmt = status_formats[level];
    printf(fmt, count);
}

void print_header(int width)
{
    const char *hdr = "%-*s|\n";
    printf(hdr, width, "name");
}
