#pragma once
namespace geo {
class Shape {
public:
    virtual ~Shape() = default;
    virtual double area() const = 0;
};

class Circle final : public geo::Shape {
public:
~>    ~Circle();
    double area() const override;
};
}
