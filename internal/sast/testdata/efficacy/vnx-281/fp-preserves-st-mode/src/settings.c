#include <stdio.h>
#include <sys/stat.h>

int save_settings(const char *path, const char *body) {
    char tmp[4096];
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    FILE *out = fopen(tmp, "w");
    if (out == NULL) return -1;
    fputs(body, out);
    fchmod(fileno(out), st.st_mode & 07777);
    fclose(out);
    return rename(tmp, path);
}

int copy_over(const char *dst, mode_t mode, const char *body) {
    char tmp[256];
    snprintf(tmp, sizeof tmp, "%s.tmp", dst);
    FILE *f = fopen(tmp, "w");
    fputs(body, f);
    fclose(f);
    chmod(tmp, mode);
    return rename(tmp, dst);
}
