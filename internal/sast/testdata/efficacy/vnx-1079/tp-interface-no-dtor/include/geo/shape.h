#pragma once

namespace geo {

~>class Shape {
public:
    virtual double area() const = 0;
    virtual const char *name() const { return "shape"; }
};

~>struct Visitor
{
    virtual void visit(Shape &s) = 0;
};

}  // namespace geo
