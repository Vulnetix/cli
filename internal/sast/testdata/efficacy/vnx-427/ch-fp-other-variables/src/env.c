#include <stdlib.h>

void tidy_env(void)
{
    unsetenv("LD_PRELOAD");
    setenv("MANPATH", ".", 1);
    setenv("PATH_INFO", "./index", 1);
    const char *libdir = getenv("ACME_LIB_DIR");
    setenv("LD_LIBRARY_PATH", libdir, 1);
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    const char *path = getenv("PATH");
    (void)path;
}
