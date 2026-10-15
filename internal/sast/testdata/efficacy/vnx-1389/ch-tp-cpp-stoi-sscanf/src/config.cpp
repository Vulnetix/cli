#include <string>
#include <cstdio>

int parse_port(const std::string &arg) {
~>    int port = std::stoi(arg, nullptr, 0);
    return port;
}

unsigned long parse_mask(const std::string &text) {
~>    return std::stoul(text, nullptr, 0);
}

int read_count(const char *buf) {
    int n = 0;
~>    if (sscanf(buf, "%i", &n) != 1) {
        return -1;
    }
    return n;
}

long base_zero(const char *s) {
    char *end;
~>    long v = strtoll(s,&end,0);
    return v;
}
