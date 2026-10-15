#include <stdio.h>

typedef char *strbuf;

void dump_json(const char *path)
{
    FILE *out = fopen(path, "w");
    fputs("{}", out);
    fclose(out);
}

static size_t buflen(strbuf b);

void show(strbuf reply)
{
    strbuf out;
    out = reply;
    fwrite(out, buflen(out), 1, stdout);
}
