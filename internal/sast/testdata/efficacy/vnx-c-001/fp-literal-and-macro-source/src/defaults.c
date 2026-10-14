#include <string.h>

#define VERSION_STRING "4.2.1"
#define SUFFIX ".bak"

void defaults(char *out, char *ver, char *path, wchar_t *wout, int verbose)
{
    char buf[64];

    strcpy(buf, "default");
    strcpy(buf, "");
    strcat(path, "/");
    strcpy(ver, VERSION_STRING);
    strcat(path, SUFFIX);
    strcpy(out, VERSION_STRING "-" SUFFIX);
    strcpy(out, verbose ? "verbose" : "quiet");
    wcscpy(wout, L"wide");
}
