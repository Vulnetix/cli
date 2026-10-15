#include <stdio.h>

int export_report(const char *path, const char *body) {
    FILE *out = fopen(path, "w");
    if (!out) return -1;
    fputs(body, out);
    fclose(out);
    return 0;
}

int archive_log(const char *from, const char *to) {
    /* the log already exists with its own mode; moving keeps it */
    return rename(from, to);
}
