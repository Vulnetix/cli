#include <string>

~>struct Plugin {
    explicit Plugin(std::string name);
    ~Plugin();
    virtual void run() = 0;
    std::string name_;
};

~>class Codec {
    int level_ = 0;
public:
    Codec() = default;
    ~Codec() { flush(); }
    virtual int encode(const char *in, char *out);
private:
    void flush();
};
