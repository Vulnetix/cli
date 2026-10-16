#pragma once
#include <string>

class TempPath {
public:
    static std::string mktemp(const std::string &prefix);
    std::string tmpnam() const;
};

inline std::string use(TempPath &p)
{
    return p.tmpnam();
}
