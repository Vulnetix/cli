#include <stdio.h>
#include <string.h>

int save_settings(const char *path, const char *body) {
    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    FILE *out = fopen(tmp, "w");
    if (out == NULL) {
        return -1;
    }
    fputs(body, out);
    fclose(out);
~>    if (rename(tmp, path) != 0) {
        return -1;
    }
    return 0;
}
