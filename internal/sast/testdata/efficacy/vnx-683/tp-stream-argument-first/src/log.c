#include <stdio.h>

void log_line(FILE *fp, const char *msg, const char *buf, size_t n) {
~>    fputs(stderr, msg);
~>    fwrite(fp, buf, 1, n);
~>    fread(stdin, buf, 1, n);
~>    fputc(fp, 'x');
}
