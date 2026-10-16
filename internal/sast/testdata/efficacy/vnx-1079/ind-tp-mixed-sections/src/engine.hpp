#pragma once
#include <string>
~>struct Engine {
    virtual void start();
    virtual void stop();
    ~Engine();
protected:
    std::string name_;
private:
    int fd_ = -1;
};
