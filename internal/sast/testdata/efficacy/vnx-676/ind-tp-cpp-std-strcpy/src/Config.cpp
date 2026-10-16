#include <cstring>
#include <string>

class Config {
public:
    void setHost(const std::string &host)
    {
~>        std::strcpy(host_, host.c_str());
    }

private:
    char host_[64];
};
