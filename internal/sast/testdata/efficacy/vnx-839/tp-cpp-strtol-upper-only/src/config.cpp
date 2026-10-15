#include <cstdlib>
#include <string>

std::string Config::channel(const char *value) const
{
    int ch = static_cast<int>(std::strtol(value, nullptr, 10));
~>    if (ch < kChannels) {
        return channels_[ch];
    }
    return {};
}
