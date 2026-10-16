#include <unistd.h>
#include <dirent.h>
#include <string>

void Connection::shutdown()
{
    ::close(fd_);
    connected_ = false;
    stats_.closed++;
~>    ::close(fd_);
}

int count_entries(const std::string &path)
{
    DIR *d = opendir(path.c_str());
    int n = 0;
    while (readdir(d) != nullptr)
        n++;
    closedir(d);
~>    closedir(d);
    return n;
}
