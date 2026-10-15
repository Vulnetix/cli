#pragma once
#include <cstring>

class Buffer {
public:
    explicit Buffer(std::size_t n) : data_(new char[n]), size_(n) {}
    Buffer(const Buffer& other) : data_(new char[other.size_]), size_(other.size_) {
        std::memcpy(data_, other.data_, size_);
    }
    Buffer& operator=(Buffer other) { swap(other); return *this; }
    ~Buffer() { delete[] data_; }

private:
    void swap(Buffer& o);
    char* data_;
    std::size_t size_;
};

// ~Legacy() { delete p; } was removed
class Logger {
public:
    ~Logger() { flush(); }
    void flush();
};
