#include <fcntl.h>
#include <unistd.h>
#include <cstdlib>
#include <string>

class ArtifactCache {
public:
    bool open_dir(const std::string &root)
    {
~>        dir_fd_ = ::openat(AT_FDCWD, root.c_str(), O_RDONLY | O_DIRECTORY);
        return dir_fd_ >= 0;
    }

    int prune(const std::string &root)
    {
        std::string cmd = "find " + root + " -mtime +7 -delete";
        return std::system(cmd.c_str());
    }

private:
    int dir_fd_ = -1;
};
