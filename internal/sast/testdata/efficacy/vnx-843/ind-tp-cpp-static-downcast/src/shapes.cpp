struct Shape { virtual ~Shape() {} int kind_ = 0; };
struct Circle : Shape { double radius = 1.0; };
struct Square : Shape { double side = 1.0; };

double circle_area(Shape *s)
{
~>    Circle *c = static_cast<Circle *>(s);
    return 3.14159 * c->radius * c->radius;
}
