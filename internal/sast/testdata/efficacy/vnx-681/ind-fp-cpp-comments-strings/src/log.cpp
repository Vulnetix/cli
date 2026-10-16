#include <cstdint>
#include <string>

// uint16_t n = strlen(s);   historical bug
const char *note = "int size = ftell(fp);";

uint32_t measure(const std::string &s)
{
    /* uint8_t b = (uint8_t)strlen(name); */
    uint32_t n = s.size();
    size_t m = s.length();
    return n + m;
}
