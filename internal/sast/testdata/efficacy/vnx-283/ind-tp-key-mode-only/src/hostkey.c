#include <stdio.h>
#include <sys/stat.h>
#include "log.h"

int load_host_key(const char *path, struct key **out)
{
    struct stat st;

    if (stat(path, &st) != 0) {
        log_error("cannot stat %s", path);
        return -1;
    }
~>    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        log_error("%s: permissions too open", path);
        return -1;
    }
    return key_read_pem(path, out);
}
