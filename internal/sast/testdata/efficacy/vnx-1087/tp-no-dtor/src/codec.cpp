#include <string>

~>class Codec {
public:
    virtual std::string encode(const std::string& in) const;
    virtual std::string decode(const std::string& in) const;
};

std::string Codec::encode(const std::string& in) const { return in; }
