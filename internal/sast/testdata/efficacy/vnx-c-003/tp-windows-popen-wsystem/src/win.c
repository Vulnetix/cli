#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

void open_report(const char *name)
{
    char cmd[260];
    FILE *p;

    _snprintf(cmd, sizeof(cmd), "type reports\\%s.txt", name);
~>    p = _popen(cmd, "rt");
    _pclose(p);
}

void delete_file(const wchar_t *name)
{
    wchar_t wcmd[260];

    swprintf(wcmd, 260, L"del /q %ls", name);
~>    _wsystem(wcmd);
}
