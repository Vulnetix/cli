#include <stdio.h>
#include <sys/stat.h>

int secrets_write(const char *path, const char *body)
{
    char tmp[1024];
    mode_t old = umask(077);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *out = fopen(tmp, "w");
    umask(old);
    if (!out)
        return -1;
    fputs(body, out);
    fclose(out);
    return rename(tmp, path);
}
