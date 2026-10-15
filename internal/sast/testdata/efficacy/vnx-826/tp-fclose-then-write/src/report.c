#include <stdio.h>

int save_report(const char *path, const char *body)
{
    FILE *out = fopen(path, "w");
    if (out == NULL) {
        return -1;
    }
    fputs(body, out);
~>    fclose(out);
    fprintf(out, "\n-- end of report --\n");
    return 0;
}

void copy_header(FILE *src, FILE *dst)
{
    char line[256];
~>    if (fclose(src) != 0)
        perror("close source");
    while (fgets(line, sizeof line, src) != NULL) {
        fputs(line, dst);
    }
}
