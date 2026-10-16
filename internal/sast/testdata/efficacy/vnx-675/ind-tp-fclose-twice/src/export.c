#include <stdio.h>

int export_rows(const char *path, int n) {
    FILE *fp = fopen(path, "w");
    if (!fp) return -1;
    fprintf(fp, "%d\n", n);
    fclose(fp);
    log_info("exported %d rows", n);
~>    fclose(fp);
    return 0;
}
