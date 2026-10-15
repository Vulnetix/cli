#pragma once
#include <windows.h>
#include <dlfcn.h>
#include <cstdlib>

namespace acme {
inline void *LoadCodec()
{
~>    HMODULE shim = ::LoadLibraryA("acmecodec.dll");
~>    void *plugin = ::dlopen("../lib/libacme_plugin.so", RTLD_NOW | RTLD_GLOBAL);
~>    ::SetEnvironmentVariableA("PATH", ".;C:\\Windows\\System32");
    return shim ? (void *)shim : plugin;
}
}
