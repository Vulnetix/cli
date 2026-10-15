#pragma once
#include <cstdio>
#include <fstream>
#include <string>

inline bool atomic_replace(const std::string &dest, const std::string &text) {
    const std::string pending = dest + ".pending";
    {
        std::ofstream sink{pending, std::ios::out | std::ios::binary};
        sink << text;
    }
~>    return std::rename(pending.c_str(), dest.c_str()) == 0;
}
