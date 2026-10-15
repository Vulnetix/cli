#include <sys/stat.h>
#include <unistd.h>

bool SocketDirIsPrivate(int dirfd) {
    struct stat st{};
    if (fstat(dirfd, &st) != 0) return false;
    const bool owned = st.st_uid == geteuid();
    const bool closed = (st.st_mode & 0077) == 0;
    return owned && closed;
}
