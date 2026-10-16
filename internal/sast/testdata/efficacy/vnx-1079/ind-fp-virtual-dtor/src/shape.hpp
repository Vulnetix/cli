#pragma once
class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
};
class Logger {
public:
    virtual
    ~Logger();
    virtual void log(const char *m);
};
