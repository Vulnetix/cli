#include <cstdlib>
#include <fcntl.h>
#include <string>

void Backup::start(const std::string &dir)
{
~>    lock_fd_ = ::open((dir + "/.lock").c_str(), O_RDWR | O_CREAT, 0600);
    std::string cmd = "tar czf /tmp/backup.tgz " + dir;
    std::system(cmd.c_str());
}
