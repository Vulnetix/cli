class Base {
public:
    virtual ~Base() = default;
};

class Leaf : public Base {
public:
    void go();
    // ~Leaf();
};

Leaf::~Leaf() {}
