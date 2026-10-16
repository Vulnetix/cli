#include <windows.h>
#include <stdio.h>

static HMODULE g_codec;

int codec_load(void)
{
~>    g_codec = LoadLibraryExA("vpxcodec.dll", NULL, 0);
    if (!g_codec) {
        fprintf(stderr, "codec: load failed (%lu)\n", GetLastError());
        return -1;
    }
    return 0;
}
