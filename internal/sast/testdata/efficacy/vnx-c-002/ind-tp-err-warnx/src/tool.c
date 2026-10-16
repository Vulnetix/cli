#include <err.h>
#include <stdio.h>
#include <string.h>

void report_bad_input(const char *line)
{
    char detail[200];
    snprintf(detail, sizeof(detail), "bad record: %s", line);
~>    warnx(detail);
}
