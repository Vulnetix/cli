#include <string>

~>struct Plugin {
    explicit Plugin(std::string name);
    ~Plugin();
    virtual void run() = 0;
    std::string name_;
};
