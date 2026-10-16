#include <dlfcn.h>
#include <stddef.h>

void *open_tls_backend(void)
{
    void *h = dlopen("libssl.so.3", RTLD_NOW | RTLD_GLOBAL);
    if (h == NULL) {
        h = dlopen("/usr/lib/x86_64-linux-gnu/libssl.so.3", RTLD_NOW | RTLD_GLOBAL);
    }
    return h;
}

void *open_zlib(void)
{
    /* never dlopen("./libz.so") here: the cwd is attacker controlled */
    return dlopen("libz.so.1", RTLD_LAZY);
}
