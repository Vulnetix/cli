#pragma once
#include <cstddef>

template <typename T>
class Stack {
public:
    explicit Stack(std::size_t cap) : data_(new T[cap]), cap_(cap) {}
~>    ~Stack() { delete[] data_; }

    void push(const T& v) { data_[size_++] = v; }

private:
    T* data_;
    std::size_t cap_;
    std::size_t size_ = 0;
};
