#include "base.h"

class Point {
public:
    Point(int x, int y) : x_(x), y_(y) {}
    ~Point() {}
    int x_, y_;
};

class Circle : public Shape {
public:
    virtual double area() const override { return 3.14 * r_ * r_; }
    double r_ = 1;
};

class Leaf final {
public:
    virtual void tick();
};

class Forward;
struct Config;
