#pragma once
#include "base.hpp"

class FilePlugin
    : public Plugin {
public:
    void load() override;
};

class MemorySink final {
public:
    virtual void write(const char*) {}
};

struct Point {
    int x;
    int y;
    int virtualIndex;
};
