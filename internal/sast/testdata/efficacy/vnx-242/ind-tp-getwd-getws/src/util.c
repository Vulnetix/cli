#include <stdio.h>
#include <unistd.h>
#include <wchar.h>

void print_cwd(void)
{
    char dir[256];
~>    getwd(dir);
    printf("%s\n", dir);
}

void read_wide(void)
{
    wchar_t buf[80];
~>    _getws(buf);
    wprintf(L"%ls\n", buf);
}
