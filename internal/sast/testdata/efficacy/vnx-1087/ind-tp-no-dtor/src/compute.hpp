#pragma once
#include <string>

~>class Engine {
public:
    explicit Engine(std::string name) : name_(std::move(name)) {}
    virtual int compute() const;
    std::string name() const { return name_; }
private:
    std::string name_;
};
