#include <stdio.h>
#include "log.h"

int export_rows(const char *path, const struct row *rows, int n)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    for (int i = 0; i < n; i++)
        fprintf(fp, "%d,%s\n", rows[i].id, rows[i].name);
    fclose(fp);
    log_info("exported %d rows", n);
~>    fclose(fp);
    return 0;
}
