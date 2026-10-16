#pragma once
#include <memory>
#include <vector>

class Modern {
public:
    ~Modern() = default;
private:
    std::unique_ptr<int[]> a_;
    std::vector<char> b_;
};

class Logger {
public:
    ~Logger() { flush(); }
    // ~Logger() { delete sink_; } was removed
    void flush();
};
