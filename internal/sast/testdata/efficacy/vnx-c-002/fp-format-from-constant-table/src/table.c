#include <stdio.h>

static const char usage_text[] = "usage: tool [options]\n";
static const char *row_formats[] = { "%-10s %5d\n", "%s,%d\n" };

void print_row(const char *name, int count, int csv)
{
    const char *fmt = "%-10s %5d\n";
    const char *banner = csv ? "name,count\n" : "NAME       COUNT\n";

    printf(fmt, name, count);
    printf(banner);
    printf(row_formats[csv], name, count);
    printf(usage_text);
}
