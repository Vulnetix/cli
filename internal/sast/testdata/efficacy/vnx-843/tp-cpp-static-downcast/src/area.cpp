#include <memory>

class Shape {
public:
    virtual ~Shape() = default;
    virtual int kind() const = 0;
};

class Circle : public Shape {
public:
    double radius = 0;
    int kind() const override { return 1; }
};

class Square final : public Shape {
public:
    double side = 0;
    int kind() const override { return 2; }
};

double circle_area(Shape *s)
{
~>    Circle *c = static_cast<Circle *>(s);
    return 3.14159 * c->radius * c->radius;
}

double square_area(const Shape &shape)
{
~>    const Square &sq = static_cast<const Square &>(shape);
    return sq.side * sq.side;
}

double legacy_radius(Shape* s)
{
~>    return ((Circle*)s)->radius;
}
