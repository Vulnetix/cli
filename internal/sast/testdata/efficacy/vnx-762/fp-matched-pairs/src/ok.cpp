#include <cstdlib>
#include <cstring>

void ok() {
    char *a = new char[64];
    delete[] a;
    Widget *w = new Widget();
    delete w;
    char *m = (char *)malloc(10);
    free(m);
    char *s = strdup("x");
    free(s);
    char *t = new char[8];
    delete [] t;
    // free(a) would be wrong here: a came from new[]
}
