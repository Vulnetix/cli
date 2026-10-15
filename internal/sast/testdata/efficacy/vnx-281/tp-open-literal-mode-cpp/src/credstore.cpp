#include <fcntl.h>
#include <unistd.h>
#include <cstdio>
#include <string>

bool CredStore::Flush(const std::string &target) {
    std::string staging = target + ".tmp";
    int fd = ::open(staging.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                    0644);
    if (fd < 0) return false;
    ::write(fd, buffer_.data(), buffer_.size());
    ::fsync(fd);
    ::close(fd);
~>    return std::rename(staging.c_str(), target.c_str()) == 0;
}

int rewrite_keys(const char *keyfile, const char *data, size_t len) {
    char staged[512];
    snprintf(staged, sizeof staged, "%s~", keyfile);
    int fd = creat(staged, 0666);
    write(fd, data, len);
    close(fd);
~>    return rename(staged,keyfile);
}
