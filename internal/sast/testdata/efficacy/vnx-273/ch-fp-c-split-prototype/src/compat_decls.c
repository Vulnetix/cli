#include <sys/types.h>

extern int
setgroups(size_t size, const gid_t *list);
extern int
initgroups(const char *user, gid_t group);
