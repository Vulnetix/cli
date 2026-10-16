#include <stdio.h>

void cleanup(FILE *in, FILE *out) {
    fclose(in);
    fclose(out);
    /* fclose(out); */
    const char *doc = "fclose(in); fclose(in);";
    (void)doc;
}

void cases(int mode, FILE *f) {
    switch (mode) {
    case 1:
        fclose(f);
        break;
    case 2:
        fclose(f);
        break;
    }
}
