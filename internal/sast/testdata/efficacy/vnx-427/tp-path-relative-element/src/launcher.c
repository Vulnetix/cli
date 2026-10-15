#include <stdlib.h>
#include <unistd.h>

int prepare_env(void)
{
~>    setenv("PATH", ".:/usr/local/bin:/usr/bin:/bin", 1);
~>    putenv("PATH=/usr/local/bin::/usr/bin");
~>    setenv("LD_LIBRARY_PATH", "./lib:/opt/app/lib", 1);
~>    setenv("PATH", "/usr/bin:/bin:", 1);
    return execlp("helper", "helper", (char *)NULL);
}
