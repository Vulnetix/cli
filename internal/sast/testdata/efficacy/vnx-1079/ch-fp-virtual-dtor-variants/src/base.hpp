#pragma once

class Plugin {
public:
    virtual ~Plugin() noexcept = default;
    virtual void load() = 0;
};

struct Visitor
{
    virtual
    ~Visitor() {}
    virtual void visit(int) = 0;
};

class Sink {
protected:
    ~Sink() = default;
public:
    virtual void write(const char*) = 0;
};
