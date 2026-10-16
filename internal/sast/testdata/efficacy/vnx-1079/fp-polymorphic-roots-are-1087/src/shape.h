#ifndef SHAPE_H
#define SHAPE_H

struct Shape {
    Shape() = default;
    ~Shape() = default;
    virtual double area() const { return 0.0; }
    virtual const char* name() const = 0;
};

#endif
