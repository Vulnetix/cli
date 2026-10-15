#include <fcntl.h>
#include <string.h>

int open_default_config(void)
{
    char path[256];
    strlcpy(path, "/etc/acme/acme.conf", sizeof(path));
    return open(path, O_RDONLY);
}
