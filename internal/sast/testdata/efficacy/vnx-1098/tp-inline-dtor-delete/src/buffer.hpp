#pragma once
#include <cstddef>

class Buffer {
public:
    explicit Buffer(std::size_t n) : data_(new char[n]), size_(n) {}
~>    ~Buffer() { delete[] data_; }

    char* data() { return data_; }

private:
    char* data_;
    std::size_t size_;
};
