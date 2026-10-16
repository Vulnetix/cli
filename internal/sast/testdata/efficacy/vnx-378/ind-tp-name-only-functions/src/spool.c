#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int spool_report(const char *body)
{
    char tmpl[] = "/tmp/rptXXXXXX";
~>    char *name = tempnam("/var/tmp", "rpt");
    FILE *out;

    if (name == NULL)
        return -1;
~>    if (mktemp(tmpl) == NULL || tmpl[0] == '\0') {
        free(name);
        return -1;
    }
    out = fopen(name, "w");
    if (out == NULL) {
        free(name);
        return -1;
    }
    fputs(body, out);
    fclose(out);
    free(name);
    return 0;
}

const char *scratch_name(char *buf)
{
~>    return tmpnam_r(buf);
}
