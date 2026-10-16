struct Shape { virtual ~Shape() {} int kind_ = 0; };
struct Circle : Shape { double radius = 1.0; };
struct Square : Shape { double side = 1.0; };

double maybe_circle(Shape *s)
{
    Circle *c = dynamic_cast<Circle *>(s);
    if (!c)
        return 0.0;
    return c->radius;
}

double tagged(Shape *s)
{
    if (s->kind_ == 1) {
        Circle *c = static_cast<Circle *>(s);
        return c->radius;
    }
    return 0.0;
}
