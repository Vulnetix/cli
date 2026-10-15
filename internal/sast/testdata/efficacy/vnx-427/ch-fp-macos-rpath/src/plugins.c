#include <dlfcn.h>

void *load_bundle_libs(void)
{
    void *a = dlopen("@rpath/libAcmeCore.dylib", RTLD_NOW);
    void *b = dlopen("@executable_path/../Frameworks/libAcmeUI.dylib", RTLD_LAZY);
    void *c = dlopen("@loader_path/libAcmeNet.dylib", RTLD_NOW);
    return a ? a : (b ? b : c);
}
