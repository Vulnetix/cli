#include <cstdio>
#include <unistd.h>

void read_line(wchar_t *out) {
~>    _getws(out);
~>    std::gets(narrow);
    char dir[256];
~>    getwd(dir);
}
