#include <stdio.h>
#include <string.h>
#include <unistd.h>

int state_save(const char *state_path, const char *json)
{
    char tmpl[512];
    snprintf(tmpl, sizeof tmpl, "%s.XXXXXX", state_path);
    int fd = mkstemp(tmpl);          /* created 0600 */
    if (fd < 0)
        return -1;
    size_t len = strlen(json);
    if (write(fd, json, len) != (ssize_t)len || fsync(fd) != 0) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    close(fd);
    return rename(tmpl, state_path);
}
