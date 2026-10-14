#ifndef GFX_SHAPE_H
#define GFX_SHAPE_H

namespace gfx {

class Shape {
public:
    virtual
    ~Shape();
    virtual double area() const = 0;
};

}  // namespace gfx

#endif
