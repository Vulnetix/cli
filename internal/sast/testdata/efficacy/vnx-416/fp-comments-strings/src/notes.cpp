#include <string>

void notes(char *buf)
{
    // tmp = realloc(buf, 10); buf[0] = 1;
    /* const char *p = std::to_string(1).c_str(); */
    puts("const char *p = std::to_string(1).c_str();");
    puts("q = realloc(p, 2); p[0] = 0;");
}
