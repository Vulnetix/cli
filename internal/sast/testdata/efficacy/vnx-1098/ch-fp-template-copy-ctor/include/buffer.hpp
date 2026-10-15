#pragma once
#include <algorithm>
#include <cstddef>

template <typename T>
class Buffer {
public:
    explicit Buffer(std::size_t n) : n_(n), p_(new T[n]) {}
    Buffer(const Buffer<T>& other) : n_(other.n_), p_(new T[other.n_]) {
        std::copy(other.p_, other.p_ + n_, p_);
    }
    Buffer<T>& operator=(Buffer<T> other) {
        std::swap(p_, other.p_);
        std::swap(n_, other.n_);
        return *this;
    }
    ~Buffer() { delete[] p_; }

private:
    std::size_t n_;
    T* p_;
};
