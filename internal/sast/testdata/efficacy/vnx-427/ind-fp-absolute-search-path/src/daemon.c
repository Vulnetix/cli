#include <stdlib.h>
#include <stdio.h>

static const char *usage_text = "set LD_PRELOAD=./hook.so to debug";

int daemon_init(int argc, char **argv)
{
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("LD_LIBRARY_PATH", "/opt/acme/lib:/usr/lib", 1);
    if (argc > 1) {
        setenv("TZ", argv[1], 1);
    }
    unsetenv("LD_PRELOAD");
    puts(usage_text);
    return 0;
}
