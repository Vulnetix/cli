#pragma once

class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
};

struct Listener {
    virtual  ~Listener() {}
    virtual void notify(int event) = 0;
};

class Stream {
public:
    virtual ~ Stream();
    virtual int read(char *buf, int n) = 0;
};
