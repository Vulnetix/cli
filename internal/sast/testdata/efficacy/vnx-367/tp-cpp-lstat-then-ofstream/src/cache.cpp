#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

void writeCache(const std::string &file, const std::string &body)
{
    struct stat st;
    if (::lstat(file.c_str(), &st) == 0 && S_ISLNK(st.st_mode)) {
        return;
    }
~>    int fd = ::open(file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ::write(fd, body.data(), body.size());
    ::close(fd);
}
