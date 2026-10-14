#pragma once
#include "shape.h"

namespace gfx {

class Circle : public gfx::Shape
{
public:
    explicit Circle(double r) : r_(r) {}
~>    ~Circle();
    double area() const override;
private:
    double r_;
};

}  // namespace gfx
