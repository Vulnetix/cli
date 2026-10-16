#include <dlfcn.h>
#include <stdio.h>

typedef int (*metrics_init_fn)(const char *);

int load_metrics_backend(const char *endpoint)
{
~>    void *handle = dlopen("plugins/libmetrics_statsd.so", RTLD_LAZY | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "metrics: %s\n", dlerror());
        return -1;
    }
    metrics_init_fn init = (metrics_init_fn)dlsym(handle, "metrics_init");
    return init ? init(endpoint) : -1;
}
