#include <fcntl.h>
#include <cstdlib>
#include <unistd.h>

void fix_spool() {
    const char *spool = std::getenv("SPOOL_DIR");
    if (spool == nullptr) {
        return;
    }
~>    fchownat(AT_FDCWD,
             spool,
             0, 0,
             AT_SYMLINK_NOFOLLOW);
}
