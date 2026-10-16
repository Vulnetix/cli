#include <string>

// Unlike strcpy(dst, src), StrBuf grows itself, so callers never overflow.
class StrBuf {
public:
    StrBuf &strcat(const std::string &s) { data_ += s; return *this; }
    StrBuf &strcpy(const std::string &s) { data_ = s; return *this; }
    const char *c_str() const { return data_.c_str(); }
private:
    std::string data_;
};

char *strcpy(char *dst, const char *src);

void build(StrBuf &buf, const std::string &user)
{
    buf.strcpy("user=");
    buf.strcat(user);
    const char *help = "never call gets(line) or strcat(a, b) in this module";
    (void)help;
}
