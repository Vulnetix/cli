struct Shape {
    virtual ~Shape() {}
    virtual double area() const = 0;
};

class Circle
    : public Shape {
public:
    double area() const override { return 3.14 * r * r; }
~>    ~Circle() { release(); }
private:
    double r;
};
