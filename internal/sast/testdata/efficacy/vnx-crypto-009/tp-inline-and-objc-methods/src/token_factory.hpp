#pragma once
#include <cstdlib>
#include <string>

class TokenFactory {
public:
    std::string makeResetToken() const {
        static const char chars[] = "abcdefghijklmnopqrstuvwxyz";
        std::string t;
        for (int i = 0; i < 24; ++i)
~>            t.push_back(chars[std::rand() % 26]);
        return t;
    }

~>    unsigned int nextNonce() { return static_cast<unsigned int>(rand()); }

    int pickShard(int n) const {
        return rand() % n;
    }
};
