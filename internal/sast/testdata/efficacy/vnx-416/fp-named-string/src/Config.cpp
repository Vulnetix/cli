#include <string>
#include <string_view>

const char *Config::name() const
{
    return name_.c_str();
}

void Config::apply(const std::string &raw)
{
    std::string_view view = raw;
    const char *data = buffer_.data();
    std::string_view sv = std::string_view(raw).substr(1);
    consume(view, data, sv);
}
