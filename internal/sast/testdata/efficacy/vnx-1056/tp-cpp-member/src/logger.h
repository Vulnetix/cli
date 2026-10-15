#pragma once
#include <cstdio>

class Logger {
public:
    void write(int severity, const char* fmt, ...);

private:
    std::FILE* stream_ = stderr;
};
