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

double area(Shape *s)
{
    if (s->kind() == 1) {
        Circle *c = static_cast<Circle *>(s);
        return 3.14159 * c->radius * c->radius;
    }
    if (auto *c = dynamic_cast<Circle *>(s)) {
        return c->radius;
    }
    return 0;
}

double area2(Shape *s)
{
    switch (s->kind()) {
    case 1:
        return static_cast<Circle *>(s)->radius;
    }
    return 0;
}
