struct Shape { virtual ~Shape() {} int kind_ = 0; };
struct Circle : Shape { double radius = 1.0; };
struct Square : Shape { double side = 1.0; };

template <class Impl>
struct Base {
    void run() { static_cast<Impl *>(this)->step(); }
};

Shape *as_shape(Circle *c)
{
    return static_cast<Shape *>(c);
}

Circle *from_handle(void *h)
{
    return static_cast<Circle *>(h);
}

// Circle *c = static_cast<Circle *>(s);  in a comment
const char *note = "static_cast<Circle *>(s)";
