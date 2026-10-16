~>#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <string.h>

static char g_name[64];

void set_service_name(const char *name)
{
    strcpy(g_name, name);
}

int main(void)
{
    char buf[128];
    sprintf(buf, "service %s starting", g_name);
    OutputDebugStringA(buf);
    return 0;
}
