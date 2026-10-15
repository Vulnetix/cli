#include <cstdio>
#include <string>
#include <sys/stat.h>

static mode_t mode_of(const std::string &p);

bool WriteConfig(const std::string &path, const std::string &body) {
    const std::string tmp = path + ".tmp";
    FILE *f = std::fopen(tmp.c_str(), "w");
    if (!f) return false;
    std::fputs(body.c_str(), f);
    fchmod(fileno(f), mode_of(path));
    std::fclose(f);
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}

bool WriteConfigCast(const std::string &path, const std::string &body, unsigned orig) {
    const std::string tmp = path + ".swap";
    FILE *f = std::fopen(tmp.c_str(), "w");
    if (!f) return false;
    std::fputs(body.c_str(), f);
    fchmod(fileno(f), (mode_t)orig);
    std::fclose(f);
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}
