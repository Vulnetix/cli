#pragma once
#include <cstring>

class Name {
public:
    Name(const char* s) : p_(new char[std::strlen(s) + 1]) { std::strcpy(p_, s); }
    Name(const Name& o) : p_(new char[std::strlen(o.p_) + 1]) { std::strcpy(p_, o.p_); }
    Name& operator=(const Name& o);
    ~Name() { delete[] p_; }
private:
    char* p_;
};
