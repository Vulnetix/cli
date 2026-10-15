#include <cstdio>

class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
};

class Circle : public Shape {
public:
    double radius = 1.0;
    double area() const override { return 3.14159 * radius * radius; }
};

class Square : public Shape {
public:
    double side = 1.0;
    double area() const override { return side * side; }
};

void grow(Shape *s)
{
~>    Circle *c = (Circle *)s;
    c->radius *= 2;
}
