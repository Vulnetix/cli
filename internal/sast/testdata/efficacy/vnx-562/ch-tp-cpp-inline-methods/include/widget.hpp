#pragma once
#include <string>

class Widget {
public:
    const char* label() const {
        std::string s = build();
~>        return s.c_str();
    }

    std::string& title() {
        std::string t = "untitled";
~>        return t;
    }

private:
    std::string build() const;
};
