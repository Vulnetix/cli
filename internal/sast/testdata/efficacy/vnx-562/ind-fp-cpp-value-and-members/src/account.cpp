#include <string>

class Account {
public:
    explicit Account(std::string name) : name_(std::move(name)) {}

    const char *name_cstr() const { return name_.c_str(); }
    const std::string &name() const { return name_; }

    std::string display() const
    {
        std::string out = "Account: " + name_;
        return out;
    }

private:
    std::string name_;
};

// Bad (do not do this): char buf[8]; return buf;
const char *usage() { return "usage: account <name>"; }
