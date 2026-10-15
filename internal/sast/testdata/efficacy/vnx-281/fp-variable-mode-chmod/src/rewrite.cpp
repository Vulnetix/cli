#include <cstdio>
#include <sys/stat.h>
#include <string>

bool Rewrite(const std::string &path, const std::string &body, mode_t original_mode) {
    std::string tmp = path + ".tmp";
    FILE *out = fopen(tmp.c_str(), "w");
    if (!out) return false;
    fwrite(body.data(), 1, body.size(), out);
    fchmod(fileno(out), original_mode);
    fclose(out);
    return std::rename(tmp.c_str(), path.c_str()) == 0;
}
