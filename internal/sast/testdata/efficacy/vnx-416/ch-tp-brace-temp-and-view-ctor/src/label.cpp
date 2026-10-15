#include <string>
#include <string_view>

void label(const char *prefix, int n)
{
~>    const char *title = std::string{prefix}.c_str();
~>    auto count_view = std::string_view(std::to_string(n));
~>    const auto *suffix = std::string(prefix, 3).data();
    draw(title, count_view, suffix);
}
