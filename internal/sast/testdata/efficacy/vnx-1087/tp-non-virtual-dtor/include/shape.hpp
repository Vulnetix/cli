#pragma once

~>class Shape {
public:
    virtual double area() const = 0;
    virtual void draw();
    ~Shape();
};
