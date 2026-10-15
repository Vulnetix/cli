#pragma once

class Shape {
public:
    virtual double area() const = 0;
    virtual ~Shape();
};

class Circle : public Shape {
public:
    double area() const override;
    ~Circle() override;
};

class Square : public Shape {
public:
    virtual double area() const;
    virtual ~Square() = default;
};
