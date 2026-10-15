#include <dlfcn.h>
#include <stdio.h>

void *load_auth(void)
{
~>    void *h = dlopen("./plugins/libauth.so", RTLD_NOW);
    if (h == NULL) {
        fprintf(stderr, "%s\n", dlerror());
    }
~>    void *codec = dlopen(
        "lib/libcodec.so",
        RTLD_LAZY | RTLD_LOCAL);
    return h ? h : codec;
}
