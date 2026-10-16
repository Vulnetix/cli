#include <stdio.h>

void write_report(const char *body)
{
    FILE *out = fopen("report.txt", "w");
    if (!out) return;
    fputs(body, out);
~>    fclose(out);
    fprintf(out, "-- end --\n");
}
