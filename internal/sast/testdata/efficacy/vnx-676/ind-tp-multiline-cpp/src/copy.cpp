#include <cstring>
#include <cstdio>

void join(char *dst, const char *prefix, const char *suffix) {
~>    strcat(dst,
           suffix);
~>    std::strcpy(dst, prefix);
}

void parse(const char *buf) {
    char key[24];
~>    sscanf(buf, "%s=%d",
           key, &value);
}
