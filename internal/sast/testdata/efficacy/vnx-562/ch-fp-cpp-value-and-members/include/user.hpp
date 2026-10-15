#pragma once
#include <string>

class User {
public:
    std::string name() const {
        std::string n = first_ + " " + last_;
        return n;
    }

    const std::string& first() const {
        return first_;
    }

    const char* last() const {
        return last_.c_str();
    }

private:
    std::string first_;
    std::string last_;
};
