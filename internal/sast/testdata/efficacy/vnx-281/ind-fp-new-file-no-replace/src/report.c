#include <stdio.h>

/* Writes a fresh report; earlier versions wrote a temp and called rename(tmp, path). */
int write_report(const char *path, const struct stats *s)
{
    FILE *fp = fopen(path, "w");
    if (!fp)
        return -1;
    fprintf(fp, "requests=%lu\nerrors=%lu\n", s->requests, s->errors);
    const char *hint = "use rename(tmp, path) for atomic replace";
    (void)hint;
    return fclose(fp);
}
