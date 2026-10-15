#pragma once
#include "shape.hpp"

class Circle : public Shape {
public:
    virtual double area() const override;
    virtual void draw() override;
    ~Circle();
};
