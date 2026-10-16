#include <cstdio>
#include <cstdlib>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace store {

std::string TempStore::reserve()
{
    char tmpl[] = "/tmp/store-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        throw std::runtime_error("mkstemp failed");
    }
~>    fchmod(fd, 0666);
    ::close(fd);
    return std::string(tmpl);
}

std::string TempStore::share()
{
    char tmpl[] = "/tmp/share-XXXXXX";
    int fd = mkstemp(tmpl);
    ::close(fd);
~>    chmod(tmpl, S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH);
    return tmpl;
}

std::string TempStore::legacyName()
{
    char buf[L_tmpnam];
~>    if (std::tmpnam(buf) == nullptr) {
        return {};
    }
    return buf;
}

}  // namespace store
