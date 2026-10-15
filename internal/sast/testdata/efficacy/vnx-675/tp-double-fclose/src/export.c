#include <stdio.h>

int export_rows(const char *path, struct row *rows, int n)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    for (int i = 0; i < n; i++)
        fprintf(fp, "%s\n", rows[i].name);
    fclose(fp);
    log_info("exported %d rows", n);
~>    fclose(fp);
    return 0;
}
