#include <cstdlib>
#include <unistd.h>
#include <string>

void hand_over(uid_t owner) {
    const char *dir = std::getenv("SPOOL_DIR");
    std::string target = std::string(dir) + "/queue";
~>    lchown(target.c_str(), owner, (gid_t)-1);
}

void direct(void) {
~>    chown(getenv("OUTPUT_FILE"), 0, 0);
}
