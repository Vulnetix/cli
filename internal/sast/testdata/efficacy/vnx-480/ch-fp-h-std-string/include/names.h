#pragma once
#include <string>

inline bool is_root(const std::string& user) {
    return user == "root";
}

inline bool is_empty_tag(const std::string& tag) { return tag != ""; }
